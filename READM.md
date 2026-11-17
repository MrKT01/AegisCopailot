# Aegis RRHH

Aplicación Flask de portafolio para autenticación, gestión de tickets, análisis documental y generación de evidencia PDF. Está diseñada como prototipo educativo, no como producto certificado para datos reales de RRHH.

## Puesta en marcha

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Completa `.env` con las claves locales antes de usar cuentas o documentos. Genera `SECRET_KEY` y `FERNET_KEY` con:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

No subas `.env`, `db.sqlite3`, adjuntos ni logs al repositorio. `.gitignore` ya los excluye para evitar futuras inclusiones; si algún secreto llegó a subirse o compartirse, considera que está comprometido y rótalo.

### Base de datos existente

El proyecto anterior usaba una clave Fernet predeterminada incluida en el código. Para conservar esos registros al cambiarla, detén Flask, guarda temporalmente la clave anterior en `OLD_FERNET_KEY` y configura la nueva en `FERNET_KEY` dentro del `.env`; ejecuta:

```powershell
python migrate_encryption.py
```

La herramienta crea respaldos fechados de SQLite y de los adjuntos antes de re-encriptar. Verifica el respaldo y la aplicación antes de borrar copias y protege esas copias como datos sensibles. Después de migrar, elimina `OLD_FERNET_KEY` del `.env`. Para un entorno nuevo sin datos, basta con configurar la clave nueva. En producción, configura además `APP_ENV=production` y una `SECRET_KEY` aleatoria de al menos 32 caracteres; el modo producción rechaza las claves de desarrollo conocidas.

### Correo de soporte

Configura `MAIL_TO`, `SMTP_USER` y `SMTP_PASS` en `.env`. Para Gmail, usa una contraseña de aplicación con verificación en dos pasos, nunca tu contraseña normal. Reinicia Flask y envía un ticket de prueba: la interfaz distingue entre guardar el ticket y enviar el correo. Los errores técnicos se registran en `logs/soporte_email.log` sin copiar el cuerpo del ticket.

### Análisis con IA externa

El análisis funciona localmente con reglas. El contenido documental no se envía al proveedor externo salvo que configures `OPENAI_API_KEY` y actives explícitamente `ALLOW_EXTERNAL_AI=true`. Revisa las obligaciones de privacidad antes de activarlo con datos personales.

## Controles implementados

- Hash de contraseñas con bcrypt y cifrado Fernet para campos sensibles de SQLite.
- Protección CSRF de formularios y del endpoint JSON del agente; cierre de sesión por POST.
- Límites de solicitudes, límites de tamaño y validación de extensión/firma de archivos.
- Cifrado de adjuntos nuevos en reposo y comprobación de propiedad del ticket al generar PDF.
- Cookies de sesión HTTP-only/SameSite, cabeceras de seguridad y cookies Secure en producción.
- La clave `SECRET_KEY` de producción no usa el valor de desarrollo.

Los límites se guardan en memoria en modo local. En producción `RATELIMIT_STORAGE_URI` es obligatorio (por ejemplo, Redis) para evitar que los límites se reinicien por proceso. Sirve la aplicación únicamente detrás de HTTPS. El agente no almacena conversaciones en la cookie ni tiene aprendizaje persistente.

En modo desarrollo, `python app.py` escucha solo en `127.0.0.1` y no activa depuración. En producción, el mismo comando usa Waitress en `127.0.0.1:5000`; coloca un proxy HTTPS delante, limita el acceso a ese puerto y configura correctamente el almacenamiento Redis.

## Pruebas

```powershell
python -m unittest discover -s tests
```

## Alcance y límites

La app no reemplaza una evaluación profesional de seguridad: SQLite local, almacenamiento local de archivos, correo SMTP y análisis heurístico no equivalen a una plataforma de producción. Antes de manejar información real se requieren revisión independiente, copias de seguridad probadas, gestión de claves dedicada, política de retención, controles de acceso operativos y verificación del despliegue HTTPS.
