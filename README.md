# Aegis RRHH

Aegis RRHH es una aplicación web desarrollada en Python con Flask para gestionar soporte interno, análisis documental y trazabilidad de incidentes en entornos de recursos humanos y seguridad operativa.

El proyecto está orientado a demostrar habilidades en backend, seguridad aplicada, manejo de archivos, validación de entradas, cifrado de datos y experiencia de usuario profesional para portafolio.

## Objetivo del proyecto

Aegis RRHH busca:

- autenticar usuarios con sesiones seguras,
- registrar tickets con evidencia adjunta,
- cifrar datos sensibles almacenados,
- analizar documentos, currículums o informes,
- generar evidencia PDF con trazabilidad del caso,
- ofrecer un asistente interno con respuestas contextuales.

## Stack tecnológico

- Python 3.14
- Flask
- Flask-Login
- Flask-Bcrypt
- Flask-WTF
- Fernet (cryptography)
- SQLite
- ReportLab
- pypdf
- SMTP / Gmail
- HTML5 / CSS / JavaScript

## Funcionalidades principales

- Registro e inicio de sesión
- Recuperación y validación de credenciales
- Cifrado de campos sensibles
- Gestión de tickets por usuario
- Adjuntos con validación de tipo y firma
- Generación de PDF de evidencia
- Análisis documental con puntuación y recomendaciones
- Asistente Aegis con respuestas locales
- Registro de eventos y trazabilidad

## Estructura del proyecto

```text
Aegis_RRHH/
├── app.py
├── migrate_encryption.py
├── requirements.txt
├── .env.example
├── .gitignore
├── READM.md
├── README.md
├── db.sqlite3
├── uploads/
├── logs/
├── static/
│   ├── mascot.js
│   └── styles.css
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── ticket_form.html
│   └── analysis.html
├── tests/
│   └── test_security.py
└── data/
    └── curriculum_falso.txt
```

## Requisitos

- Python 3.10 o superior
- pip
- acceso a un entorno local o virtual

## Instalación

1. Clona el repositorio.
2. Entra a la carpeta del proyecto.
3. Instala dependencias:

```powershell
python -m pip install -r requirements.txt
```

4. Crea tu archivo `.env` a partir de `.env.example`:

```powershell
Copy-Item .env.example .env
```

5. Configura las variables necesarias antes de ejecutar la app.

## Variables de entorno

Completa `.env` con valores reales, nunca compartas secretos en el repositorio.

```env
APP_ENV=development
SECRET_KEY=
FERNET_KEY=
MAIL_TO=
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
OPENAI_API_KEY=
ALLOW_EXTERNAL_AI=false
RATELIMIT_STORAGE_URI=memory://
```

> En producción, usa claves reales y un almacenamiento compartido para rate limiting, por ejemplo Redis.

## Ejecución local

```powershell
python app.py
```

La aplicación quedará disponible en:

```text
http://127.0.0.1:5000
```

## Seguridad incluida

- contraseñas con hash mediante bcrypt,
- cifrado Fernet para datos sensibles,
- validación de entradas y tamaños,
- control de archivos por extensión y firma,
- protección CSRF en formularios y llamadas JSON,
- cabeceras de seguridad HTTP,
- cookies HttpOnly y SameSite,
- límites de velocidad para endpoints sensibles.

## Modelo de uso

El flujo principal del sistema es:

1. registro de usuario,
2. autenticación,
3. creación de ticket,
4. archivo de evidencia adjunto,
5. almacenamiento seguro,
6. análisis documental o diagnóstico,
7. generación de evidencia PDF,
8. soporte o gestión documental.

## Notas importantes

Este proyecto está pensado como una demostración sólida de Python, seguridad y RRHH digital, pero no sustituye una evaluación profesional de seguridad para entornos con datos reales sensibles. Antes de desplegarlo en producción, es necesario revisar:

- control de acceso,
- respaldo de base de datos,
- gestión de secretos,
- almacenamiento externo seguro,
- HTTPS,
- políticas de retención,
- supervisión y auditoría.

## Pruebas

```powershell
python -m unittest discover -s tests
```

## Licencia

Proyecto para uso educativo y de portafolio.
