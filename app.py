import hashlib
import json
import os
import re
import sqlite3
import smtplib
import urllib.request
import uuid
import zipfile
from datetime import datetime
from email.message import EmailMessage
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, flash, g, jsonify, redirect, render_template, request, send_file, url_for
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from werkzeug.utils import secure_filename

try:
    from pypdf import PdfReader
except ModuleNotFoundError:
    PdfReader = None

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DB_PATH = BASE_DIR / "db.sqlite3"
UPLOAD_DIR = BASE_DIR / "uploads"
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
DEFAULT_DEV_SECRET = "aegis-rh-secret-key-2026"
DEFAULT_DEV_FERNET_KEY = "KhkJCbYSraPdfKknJ9jlmkV8FBv9wG_P3tsCuSI0-go="
APP_SECRET = os.environ.get("SECRET_KEY", "")
FERNET_KEY = os.environ.get("FERNET_KEY", "")
if APP_ENV not in {"development", "testing", "production"}:
    raise RuntimeError("APP_ENV debe ser development, testing o production.")
if APP_ENV == "production":
    if not APP_SECRET or not FERNET_KEY:
        raise RuntimeError("En producción debes configurar SECRET_KEY y FERNET_KEY fuera del código.")
    if len(APP_SECRET) < 32:
        raise RuntimeError("SECRET_KEY debe tener al menos 32 caracteres aleatorios en producción.")
    if APP_SECRET == DEFAULT_DEV_SECRET or FERNET_KEY == DEFAULT_DEV_FERNET_KEY:
        raise RuntimeError("Las claves de desarrollo conocidas no se pueden usar en producción.")
else:
    APP_SECRET = APP_SECRET or DEFAULT_DEV_SECRET
    FERNET_KEY = FERNET_KEY or DEFAULT_DEV_FERNET_KEY
MAIL_TO = os.environ.get("MAIL_TO", "aegisSeguritycopilot@gmail.com")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
ALLOW_EXTERNAL_AI = os.environ.get("ALLOW_EXTERNAL_AI", "false").strip().lower() == "true"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
MAIL_LOG = LOG_DIR / "soporte_email.log"
ANALYSIS_EXTENSIONS = {".txt", ".md", ".csv", ".pdf", ".docx"}
TICKET_EXTENSIONS = ANALYSIS_EXTENSIONS | {".png", ".jpg", ".jpeg", ".webp", ".doc"}

app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_ENV == "production"
csrf = CSRFProtect(app)
RATE_LIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
if APP_ENV == "production" and RATE_LIMIT_STORAGE_URI.startswith("memory://"):
    raise RuntimeError("En producción configura RATELIMIT_STORAGE_URI con un almacenamiento compartido, por ejemplo Redis.")
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=RATE_LIMIT_STORAGE_URI,
)

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
        "img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'"
    )
    if APP_ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

try:
    fernet = Fernet(FERNET_KEY)
except ValueError as exc:
    raise RuntimeError(
        "FERNET_KEY inválida. Debe ser una clave Fernet válida de 32 bytes en base64 URL-safe."
    ) from exc


class User(UserMixin):
    def __init__(self, user_id, name, email):
        self.id = str(user_id)
        self.name = name
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
    if not row:
        return None
    return User(row["id"], decrypt_data(row["name_cipher"]), decrypt_data(row["email_cipher"]))


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, "db"):
        g.db.close()


def init_db():
    UPLOAD_DIR.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name_cipher TEXT NOT NULL,
                email_cipher TEXT NOT NULL,
                email_hash TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subject_cipher TEXT NOT NULL,
                problem_cipher TEXT NOT NULL,
                email_cipher TEXT NOT NULL,
                attachment TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )


def encrypt_data(value):
    if value is None:
        return ""
    return fernet.encrypt(str(value).encode("utf-8")).decode("utf-8")


def decrypt_data(value):
    if not value:
        return ""
    return fernet.decrypt(value.encode("utf-8")).decode("utf-8")


def email_hash(value):
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def is_valid_email(value):
    return len(value) <= 254 and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value) is not None


def is_allowed_upload(filename, allowed_extensions, content):
    extension = Path(filename or "").suffix.lower()
    if not secure_filename(filename or "") or extension not in allowed_extensions or not content:
        return False
    if extension == ".pdf":
        return content.startswith(b"%PDF-")
    if extension in {".jpg", ".jpeg"}:
        return content.startswith(b"\xff\xd8\xff")
    if extension == ".png":
        return content.startswith(b"\x89PNG\r\n\x1a\n")
    if extension == ".webp":
        return len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP"
    if extension == ".doc":
        return content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    if extension == ".docx":
        try:
            with zipfile.ZipFile(BytesIO(content)) as archive:
                total_uncompressed = sum(item.file_size for item in archive.infolist())
                return total_uncompressed <= 25 * 1024 * 1024 and "word/document.xml" in archive.namelist()
        except (OSError, zipfile.BadZipFile):
            return False
    return b"\x00" not in content[:4096]


def store_encrypted_attachment(file_path, content):
    Path(file_path).write_bytes(fernet.encrypt(content))


def read_attachment(file_path):
    content = Path(file_path).read_bytes()
    try:
        return fernet.decrypt(content)
    except InvalidToken:
        return content


def send_ticket_email(ticket_data, file_path=None):
    if not SMTP_USER or not SMTP_PASS:
        with MAIL_LOG.open("a", encoding="utf-8") as log_file:
            log_file.write(f"\n--- {datetime.now().isoformat()} ---\nSMTP no configurado; correo no enviado.\n")
        return False

    try:
        msg = EmailMessage()
        msg["Subject"] = f"Nuevo ticket: {ticket_data['subject']}"
        msg["From"] = SMTP_USER
        msg["To"] = MAIL_TO
        msg.set_content(
            f"Nombre: {ticket_data['name']}\n"
            f"Email: {ticket_data['email']}\n\n"
            f"Asunto: {ticket_data['subject']}\n\n"
            f"Problema:\n{ticket_data['problem']}"
        )

        if file_path and os.path.exists(file_path):
            file_data = read_attachment(file_path)
            msg.add_attachment(file_data, maintype="application", subtype="octet-stream", filename=os.path.basename(file_path))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as exc:
        with MAIL_LOG.open("a", encoding="utf-8") as log_file:
            log_file.write(f"\n--- {datetime.now().isoformat()} ---\nError SMTP: {type(exc).__name__}.\n")
        return False


def get_ticket_rows(user_id=None):
    query = "SELECT * FROM tickets"
    params = []
    if user_id is not None:
        query += " WHERE user_id = ?"
        params = [user_id]
    query += " ORDER BY created_at DESC"
    rows = get_db().execute(query, params).fetchall()
    result = []
    for row in rows:
        result.append(
            {
                "id": row["id"],
                "subject": decrypt_data(row["subject_cipher"]),
                "problem": decrypt_data(row["problem_cipher"]),
                "email": decrypt_data(row["email_cipher"]),
                "attachment": row["attachment"],
                "status": row["status"],
                "created_at": row["created_at"],
            }
        )
    return result


def extract_text_from_file(file_storage):
    if file_storage is None:
        return ""

    filename = (file_storage.filename or "").lower()
    raw = file_storage.read()

    if filename.endswith((".txt", ".md", ".csv")):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="ignore")

    if filename.endswith(".docx"):
        try:
            import zipfile
            import xml.etree.ElementTree as ET

            with zipfile.ZipFile(BytesIO(raw)) as zf:
                xml_data = zf.read("word/document.xml")
            root = ET.fromstring(xml_data)
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            paragraphs = []
            for node in root.findall(".//w:t", ns):
                if node.text:
                    paragraphs.append(node.text)
            return "\n".join(paragraphs)
        except Exception:
            return ""

    if filename.endswith(".pdf") and PdfReader is not None:
        try:
            reader = PdfReader(BytesIO(raw))
            pages = []
            for page in reader.pages:
                pages.append(page.extract_text() or "")
            return "\n".join(pages)
        except Exception:
            return ""

    return ""


def generate_local_agent_reply(question):
    q = (question or "").lower()
    if any(word in q for word in ["ticket", "soporte", "correo", "mail", "problema"]):
        return "El ticket se guarda en la base de datos. Si SMTP está configurado correctamente, también se envía al correo del equipo; si falla, la pantalla lo indica y queda registrado un aviso técnico en logs."
    if any(word in q for word in ["registro", "login", "usuario", "cuenta", "sesion", "acceso"]):
        return "El acceso usa contraseñas con hash bcrypt y sesiones Flask; los campos sensibles guardados en SQLite se cifran con Fernet. No hay auditoría completa de accesos en esta versión demo."
    if any(word in q for word in ["analisis", "documento", "curriculum", "cv", "archivo"]):
        return "Puedes subir un CV o documento administrativo y el analizador revisa estructura, fortalezas, debilidades, métricas y recomendaciones prácticas."
    if any(word in q for word in ["seguridad", "cifrado", "encriptacion", "fernet", "riesgo"]):
        return "Aegis pone foco en seguridad: contraseñas hash, datos cifrados, evidencia y trazabilidad. Eso protege la integridad del sistema y la confidencialidad de la información."
    if any(word in q for word in ["ayuda", "help", "duda"]):
        return "Puedo explicarte el flujo del sistema, la seguridad, el análisis de documentos o cómo enviar un ticket correctamente."
    return "Puedo ayudarte con seguridad, sistemas de RRHH, soporte técnico, análisis documental y el flujo del proyecto. Pregúntame por cualquier parte del sistema."


def call_openai_chat(prompt, system_prompt="Eres un asistente experto en seguridad, RRHH y soporte para un portafolio profesional."):
    if not OPENAI_API_KEY or not ALLOW_EXTERNAL_AI:
        return None
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.6,
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = response.read().decode("utf-8")
            parsed = json.loads(body)
            return parsed["choices"][0]["message"]["content"].strip()
    except (HTTPError, URLError, ValueError, KeyError, TimeoutError):
        return None


def analyze_document_text(raw_text, file_name="documento"):
    text = (raw_text or "").strip()
    if not text:
        return {
            "title": file_name,
            "summary": "No se detectó texto suficiente para analizar.",
            "strengths": ["Sin evidencia analizable todavía."],
            "weaknesses": ["Agrega contenido o un archivo con texto legible."],
            "recommendations": ["Sube un documento con estructura clara para obtener análisis."],
            "score": 0,
            "structure": "Sin estructura detectada",
        }

    words = re.findall(r"\b\w+\b", text)
    sentences = re.split(r"(?<=[.!?])\s+", text)
    average_sentence = round(len(words) / max(len(sentences), 1), 2)
    lower_text = text.lower()

    sections = {
        "objetivo": any(k in lower_text for k in ["objetivo", "propósito", "perfil", "summary"]),
        "experiencia": any(k in lower_text for k in ["experiencia", "experience", "trayectoria", "logros"]),
        "educacion": any(k in lower_text for k in ["educación", "educacion", "formación", "study", "universidad"]),
        "habilidades": any(k in lower_text for k in ["habilidades", "skills", "competencias", "capacidades"]),
        "contacto": any(k in lower_text for k in ["correo", "email", "telefono", "contacto", "celular"]),
        "metas": any(k in lower_text for k in ["metas", "objetivos", "proyectos", "acciones", "prioridades"]),
    }

    strengths = []
    weaknesses = []
    recommendations = []

    if sections["objetivo"]:
        strengths.append("Incluye una intención clara y orientación profesional o institucional.")
    else:
        weaknesses.append("Falta una propuesta clara de propósito o dirección general.")

    if sections["experiencia"]:
        strengths.append("Tiene evidencia de trayectoria, desempeño o proyectos relevantes.")
    else:
        weaknesses.append("No se observan resultados o experiencia suficientemente delimitados.")

    if sections["educacion"]:
        strengths.append("La formación o preparación aparece documentada con un marco de credibilidad.")
    else:
        weaknesses.append("La formación o base académica no aparece demostrada con claridad.")

    if sections["habilidades"]:
        strengths.append("Se identifican competencias o capacidades clave para valor comercial.")
    else:
        weaknesses.append("Falta destacar habilidades principales y diferenciadoras.")

    if sections["contacto"]:
        strengths.append("La información de contacto está presente para facilitar seguimiento.")
    else:
        weaknesses.append("No se facilita un canal de contacto claro para continuidad o contratación.")

    if average_sentence > 25:
        weaknesses.append("Las frases son bastante largas; conviene dividir ideas para mejorar lectura.")
    else:
        strengths.append("La redacción tiene un ritmo legible y ordenado.")

    if len(words) < 200:
        weaknesses.append("El documento parece corto para transmitir contexto completo y profundidad.")
    elif len(words) > 1500:
        weaknesses.append("El documento es extenso y podría volverse repetitivo si no se sintetiza.")
    else:
        strengths.append("El volumen de contenido permite explicar la propuesta con suficiente profundidad.")

    missing = [name for name, present in sections.items() if not present]
    if missing:
        recommendations.append(
            "Reorganiza el documento en secciones más visibles: objetivo, experiencia, educación, habilidades y contacto."
        )
    recommendations.append("Usa viñetas, métricas y resultados concretos para elevar la credibilidad del documento.")
    recommendations.append("Resalta logros con números, procesos y valor generado para reforzar la propuesta comercial.")

    structure = ", ".join([key.title() for key, present in sections.items() if present]) or "Estructura básica insuficiente"
    score = 70
    score += min(15, sum(5 for key, present in sections.items() if present))
    score -= min(15, sum(5 for key, present in sections.items() if not present))
    score = max(0, min(100, score))

    summary = (
        f"El documento {file_name} presenta una base sólida con {len(words)} palabras y una claridad media. "
        f"Su mayor fortaleza es la presencia de estructura y valor funcional; la mejor mejora es reforzar la narrativa de resultados y la diferenciación comercial."
    )

    result = {
        "title": file_name,
        "summary": summary,
        "strengths": strengths[:5],
        "weaknesses": weaknesses[:5],
        "recommendations": recommendations[:3],
        "score": score,
        "structure": structure,
    }

    if OPENAI_API_KEY and ALLOW_EXTERNAL_AI:
        ai_summary = call_openai_chat(
            f"Actúa como analista pro y responde en español. Analiza este documento: {raw_text[:4000]}",
            system_prompt="Eres un analista experto en RRHH, talento humano, evaluación documental y seguridad. Responde en español con un resumen ejecutivo y 3 recomendaciones útiles."
        )
        if ai_summary:
            result["summary"] = ai_summary
    return result


@app.route("/")
def landing():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Completa ambos campos.")
            return redirect(url_for("login"))

        row = get_db().execute(
            "SELECT * FROM users WHERE email_hash = ?",
            (email_hash(email),),
        ).fetchone()

        if row and bcrypt.check_password_hash(row["password_hash"], password):
            user = User(row["id"], decrypt_data(row["name_cipher"]), decrypt_data(row["email_cipher"]))
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Credenciales incorrectas.")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("Todos los campos son obligatorios.")
            return redirect(url_for("register"))
        if len(name) > 120 or not is_valid_email(email):
            flash("Revisa el nombre y utiliza un correo válido.")
            return redirect(url_for("register"))
        if len(password) < 12 or len(password.encode("utf-8")) > 72:
            flash("La contraseña debe tener entre 12 caracteres y 72 bytes.")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Las contraseñas no coinciden.")
            return redirect(url_for("register"))

        existing = get_db().execute(
            "SELECT id FROM users WHERE email_hash = ?",
            (email_hash(email),),
        ).fetchone()

        if existing:
            flash("Este correo ya está registrado.")
            return redirect(url_for("register"))

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        get_db().execute(
            "INSERT INTO users (name_cipher, email_cipher, email_hash, password_hash) VALUES (?, ?, ?, ?)",
            (encrypt_data(name), encrypt_data(email), email_hash(email), password_hash),
        )
        get_db().commit()
        flash("Registro exitoso. Ya puedes iniciar sesión.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada.")
    return redirect(url_for("landing"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user
    rows = get_ticket_rows(user_id=int(user.id))
    return render_template("dashboard.html", user=user, tickets=rows)


@app.route("/analysis", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def analysis():
    result = None
    if request.method == "POST":
        uploaded_file = request.files.get("document")
        document_text = request.form.get("document_text", "").strip()
        if len(document_text) > 50000:
            flash("El texto supera el máximo de 50.000 caracteres.")
            return redirect(url_for("analysis"))

        if uploaded_file and uploaded_file.filename:
            file_content = uploaded_file.read()
            if not is_allowed_upload(uploaded_file.filename, ANALYSIS_EXTENSIONS, file_content):
                flash("Tipo de archivo no permitido o formato inválido.")
                return redirect(url_for("analysis"))
            uploaded_file.stream.seek(0)
            document_text = extract_text_from_file(uploaded_file) or document_text

        if not document_text:
            flash("Sube un documento o pega el texto para analizarlo.")
            return redirect(url_for("analysis"))

        result = analyze_document_text(document_text, (uploaded_file.filename if uploaded_file and uploaded_file.filename else "Documento"))

    return render_template("analysis.html", result=result)


@app.route("/ticket", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def ticket_form():
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        problem = request.form.get("problem", "").strip()
        email = request.form.get("email", "").strip()
        uploaded_file = request.files.get("attachment")

        if not subject or not problem or not email:
            flash("Asunto, problema y correo son obligatorios.")
            return redirect(url_for("ticket_form"))
        if len(subject) > 160 or len(problem) > 10000 or not is_valid_email(email):
            flash("Revisa el asunto, la descripción y el correo de contacto.")
            return redirect(url_for("ticket_form"))

        relative_path = ""
        if uploaded_file and uploaded_file.filename:
            file_content = uploaded_file.read()
            if not is_allowed_upload(uploaded_file.filename, TICKET_EXTENSIONS, file_content):
                flash("Adjunto no permitido o formato inválido. Usa PDF, DOC/DOCX, TXT, CSV o imagen PNG/JPG/WebP.")
                return redirect(url_for("ticket_form"))
            stored_name = secure_filename(uploaded_file.filename)
            file_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{stored_name}"
            store_encrypted_attachment(file_path, file_content)
            relative_path = str(file_path.name)

        with get_db() as conn:
            conn.execute(
                "INSERT INTO tickets (user_id, subject_cipher, problem_cipher, email_cipher, attachment, status) VALUES (?, ?, ?, ?, ?, 'open')",
                (
                    int(current_user.id),
                    encrypt_data(subject),
                    encrypt_data(problem),
                    encrypt_data(email),
                    relative_path,
                ),
            )
            conn.commit()

        ticket_payload = {
            "name": current_user.name,
            "email": email,
            "subject": subject,
            "problem": problem,
        }
        email_sent = send_ticket_email(
            ticket_payload,
            str(UPLOAD_DIR / relative_path) if relative_path else None,
        )
        if email_sent:
            flash("Ticket guardado y correo enviado al equipo.")
        else:
            flash("Ticket guardado, pero no se pudo enviar el correo. Revisa la configuración SMTP y los logs.")
        return redirect(url_for("dashboard"))

    return render_template("ticket_form.html", user=current_user)


@app.route("/agent/chat", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def agent_chat():
    payload = request.get_json(silent=True) or {}
    question = (payload.get("message") or "").strip()
    if not question:
        return jsonify({"reply": "¿Qué parte del sistema quieres que te explique?"})
    if len(question) > 1000:
        return jsonify({"reply": "La pregunta es demasiado larga; limita el mensaje a 1.000 caracteres."}), 400

    ai_reply = call_openai_chat(
        f"Responde en español como asistente de un sistema de seguridad y RRHH. Pregunta del usuario: {question}",
        system_prompt="Eres Aegis, un asistente experto en seguridad, RRHH, atención al cliente y automatización. Explica la parte del sistema con claridad y de forma práctica."
    )
    if not ai_reply:
        ai_reply = generate_local_agent_reply(question)

    return jsonify({"reply": ai_reply})


@app.route("/ticket/<int:ticket_id>/pdf")
@login_required
def ticket_pdf(ticket_id):
    row = get_db().execute("SELECT * FROM tickets WHERE id = ? AND user_id = ?", (ticket_id, int(current_user.id))).fetchone()
    if not row:
        flash("No se encontró ese ticket.")
        return redirect(url_for("dashboard"))

    subject = decrypt_data(row["subject_cipher"])
    problem = decrypt_data(row["problem_cipher"])
    email = decrypt_data(row["email_cipher"])
    attachment_name = row["attachment"]

    pdf_buffer = BytesIO()
    pdf = canvas.Canvas(pdf_buffer)
    pdf.setTitle(f"Ticket - {subject}")
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(60, 780, "Aegis RRHH - Ticket de soporte")
    pdf.setFont("Helvetica", 12)
    pdf.drawString(60, 740, f"Asunto: {subject}")
    pdf.drawString(60, 720, f"Email: {email}")
    pdf.drawString(60, 700, f"Estado: {row['status']}")
    pdf.drawString(60, 660, "Describa el problema:")
    text = pdf.beginText(60, 630)
    for line in problem.splitlines():
        text.textLine(line[:90])
    pdf.drawText(text)

    if attachment_name:
        pdf.drawString(60, 220, "Evidencia adjunta:")
        pdf.drawString(60, 200, attachment_name)
        attachment_path = UPLOAD_DIR / attachment_name
        if attachment_path.exists():
            try:
                if attachment_name.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                            image = ImageReader(BytesIO(read_attachment(attachment_path)))
                            pdf.drawImage(image, 60, 40, width=220, height=140, preserveAspectRatio=True)
            except Exception:
                pass

    pdf.save()
    pdf_buffer.seek(0)

    return send_file(pdf_buffer, mimetype="application/pdf", as_attachment=True, download_name=f"ticket_{ticket_id}.pdf")


init_db()


if __name__ == "__main__":
    if APP_ENV == "production":
        from waitress import serve

        serve(app, host="127.0.0.1", port=5000)
    else:
        app.run(debug=False, host="127.0.0.1", port=5000)
