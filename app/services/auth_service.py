# app/services/auth_service.py
import bcrypt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from app.database import SessionLocal
from app.models import User, Role, Sector

class AuthService:
    def __init__(self, db_session=None):
        self.db = db_session or SessionLocal()

    def register_user(self, username: str, password: str, role_name: str, sector_name: str):
        # Check if user already exists
        if self.db.query(User).filter_by(username=username).first():
            raise ValueError("El nombre de usuario ya está en uso")

        # Buscar role
        role = self.db.query(Role).filter_by(name=role_name).first()
        if not role:
            raise ValueError(f"Role '{role_name}' no existe")
        # Si sector_name no se proporciona, dejamos sector_id en None.
        if sector_name:
            sector = self.db.query(Sector).filter_by(name=sector_name).first()
            if not sector:
                raise ValueError(f"Sector '{sector_name}' no existe")
            sector_id = sector.id
        else:
            sector_id = None

        import bcrypt
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        user = User(
            username=username,
            hashed_password=hashed,
            role_id=role.id,
            sector_id=sector_id
        )
        try:
            self.db.add(user)
            self.db.commit()
            return user
        except IntegrityError:
            self.db.rollback()
            raise ValueError("El nombre de usuario ya está en uso")

    def authenticate(self, username: str, password: str):
        user = (
            self.db.query(User)
            .options(joinedload(User.role), joinedload(User.sector))
            .filter_by(username=username)
            .first()
        )
        if not user:
            raise ValueError("Usuario o contraseña incorrectos")
        if not bcrypt.checkpw(password.encode(), user.hashed_password.encode()):
            raise ValueError("Usuario o contraseña incorrectos")
        return user

    def require_admin(self, user: User):
        if user.role.name != "admin":
            raise PermissionError("Se requieren privilegios de administrador")

    def require_user_sector(self, user: User, sector_name: str):
        if user.sector.name != sector_name:
            raise PermissionError("No tienes acceso a este sector")
