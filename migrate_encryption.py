import os
import shutil
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DB_PATH = BASE_DIR / "db.sqlite3"
UPLOAD_DIR = BASE_DIR / "uploads"


def migrate_encryption(old_key, new_key, db_path=DB_PATH, upload_dir=UPLOAD_DIR):
    old_fernet = Fernet(old_key)
    new_fernet = Fernet(new_key)
    if old_key == new_key:
        raise ValueError("La clave nueva debe ser diferente de la clave anterior.")

    db_path = Path(db_path)
    upload_dir = Path(upload_dir)
    if not db_path.is_file():
        raise FileNotFoundError(f"No existe la base de datos: {db_path}")

    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_id = f"{stamp}_{uuid.uuid4().hex[:8]}"
    backup_db = db_path.with_name(f"{db_path.stem}_backup_{backup_id}{db_path.suffix}")
    backup_uploads = upload_dir.with_name(f"{upload_dir.name}_backup_{backup_id}")

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        users = connection.execute("SELECT id, name_cipher, email_cipher FROM users").fetchall()
        tickets = connection.execute(
            "SELECT id, subject_cipher, problem_cipher, email_cipher, attachment FROM tickets"
        ).fetchall()

        encrypted_users = [
            (
                new_fernet.encrypt(old_fernet.decrypt(row["name_cipher"].encode())).decode(),
                new_fernet.encrypt(old_fernet.decrypt(row["email_cipher"].encode())).decode(),
                row["id"],
            )
            for row in users
        ]
        encrypted_tickets = [
            (
                new_fernet.encrypt(old_fernet.decrypt(row["subject_cipher"].encode())).decode(),
                new_fernet.encrypt(old_fernet.decrypt(row["problem_cipher"].encode())).decode(),
                new_fernet.encrypt(old_fernet.decrypt(row["email_cipher"].encode())).decode(),
                row["id"],
            )
            for row in tickets
        ]

        encrypted_attachments = []
        upload_root = upload_dir.resolve()
        for row in tickets:
            if not row["attachment"]:
                continue
            attachment_path = upload_dir / row["attachment"]
            if attachment_path.resolve().parent != upload_root or not attachment_path.is_file():
                continue
            content = attachment_path.read_bytes()
            try:
                content = old_fernet.decrypt(content)
            except InvalidToken:
                try:
                    new_fernet.decrypt(content)
                    continue
                except InvalidToken:
                    pass
            encrypted_attachments.append((attachment_path, new_fernet.encrypt(content)))

        with sqlite3.connect(backup_db) as backup_connection:
            connection.backup(backup_connection)
        if upload_dir.is_dir():
            shutil.copytree(upload_dir, backup_uploads)

        changed_files = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany(
                "UPDATE users SET name_cipher = ?, email_cipher = ? WHERE id = ?",
                encrypted_users,
            )
            connection.executemany(
                "UPDATE tickets SET subject_cipher = ?, problem_cipher = ?, email_cipher = ? WHERE id = ?",
                encrypted_tickets,
            )
            for attachment_path, encrypted_content in encrypted_attachments:
                attachment_path.write_bytes(encrypted_content)
                changed_files.append(attachment_path)
            connection.commit()
        except Exception:
            connection.rollback()
            for attachment_path in changed_files:
                backup_path = backup_uploads / attachment_path.name
                if backup_path.exists():
                    shutil.copy2(backup_path, attachment_path)
            raise

    return backup_db, backup_uploads if backup_uploads.exists() else None


def main():
    old_key = os.environ.get("OLD_FERNET_KEY")
    new_key = os.environ.get("FERNET_KEY")
    if not old_key or not new_key:
        raise SystemExit("Configura OLD_FERNET_KEY y la nueva FERNET_KEY antes de migrar.")
    backup_db, backup_uploads = migrate_encryption(old_key.encode(), new_key.encode())
    print(f"Migración completada. Backup SQLite: {backup_db}")
    if backup_uploads:
        print(f"Backup de adjuntos: {backup_uploads}")


if __name__ == "__main__":
    main()
