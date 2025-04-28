# app/services/password_service.py
import os
from cryptography.fernet import Fernet
from sqlalchemy.exc import NoResultFound
from app.database import SessionLocal
from app.models import PasswordEntry, Sector

KEY_FILE = "secret.key"

class PasswordService:
    def __init__(self, db_session=None):
        # Carga o genera la clave de cifrado
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)
        self.db = db_session or SessionLocal()

    def _load_or_create_key(self) -> bytes:
        """Lee la clave desde disco o la crea si no existe."""
        if os.path.exists(KEY_FILE):
            return open(KEY_FILE, "rb").read()
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

    def encrypt(self, plaintext: str) -> str:
        """Devuelve el texto cifrado (string)."""
        token = self.fernet.encrypt(plaintext.encode())
        return token.decode()

    def decrypt(self, token: str) -> str:
        """Desencripta y devuelve el texto original."""
        return self.fernet.decrypt(token.encode()).decode()

    def add_entry(self, title: str, username: str, plaintext_password: str,
                  url: str, sector_name: str) -> PasswordEntry:
        """Crea y guarda una nueva entrada cifrada."""
        # Busca sector
        sector = self.db.query(Sector).filter_by(name=sector_name).first()
        if not sector:
            raise ValueError(f"Sector '{sector_name}' no existe.")

        encrypted = self.encrypt(plaintext_password)
        entry = PasswordEntry(
            title=title,
            username=username,
            encrypted_password=encrypted,
            url=url,
            sector_id=sector.id
        )
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def list_entries(self, sector_name: str = None):
        """Lista todas las entradas. Si sector_name está definido, filtra."""
        q = self.db.query(PasswordEntry)
        if sector_name:
            q = q.join(Sector).filter(Sector.name == sector_name)
        return q.all()

    def get_entry(self, entry_id: int) -> PasswordEntry:
        """Devuelve una entrada por ID (incluye campo desencriptado)."""
        entry = self.db.query(PasswordEntry).get(entry_id)
        if not entry:
            raise NoResultFound(f"Entrada con ID={entry_id} no encontrada")
        # Añadimos un atributo temporal `password` para la GUI
        entry.password = self.decrypt(entry.encrypted_password)
        return entry

    def delete_entry(self, entry_id: int):
        """Elimina la entrada indicada."""
        entry = self.db.query(PasswordEntry).get(entry_id)
        if not entry:
            raise NoResultFound(f"Entrada con ID={entry_id} no encontrada")
        self.db.delete(entry)
        self.db.commit()

    def update_entry(self, entry_id: int, **kwargs):
        """Actualiza campos (title, username, plaintext_password, url, sector_name)."""
        entry = self.db.query(PasswordEntry).get(entry_id)
        if not entry:
            raise NoResultFound(f"Entrada con ID={entry_id} no encontrada")
        if "title" in kwargs:
            entry.title = kwargs["title"]
        if "username" in kwargs:
            entry.username = kwargs["username"]
        if "plaintext_password" in kwargs:
            entry.encrypted_password = self.encrypt(kwargs["plaintext_password"])
        if "url" in kwargs:
            entry.url = kwargs["url"]
        if "sector_name" in kwargs:
            sector = self.db.query(Sector).filter_by(name=kwargs["sector_name"]).first()
            if not sector:
                raise ValueError(f"Sector '{kwargs['sector_name']}' no existe.")
            entry.sector_id = sector.id
        self.db.commit()
        self.db.refresh(entry)
        return entry
