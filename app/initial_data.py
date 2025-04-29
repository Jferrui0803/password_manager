from app.database import SessionLocal
from app.models import Role, Sector, User
import bcrypt

def init_data():
    db = SessionLocal()
    
    # Crear roles si no existen
    role_admin = db.query(Role).filter_by(name="admin").first()
    if not role_admin:
        role_admin = Role(name="admin")
        db.add(role_admin)
    
    role_user = db.query(Role).filter_by(name="user").first()
    if not role_user:
        role_user = Role(name="user")
        db.add(role_user)
    db.commit()
    
    # Crear un sector por defecto si no existe
    sector_default = db.query(Sector).filter_by(name="IT").first()
    if not sector_default:
        sector_default = Sector(name="IT")
        db.add(sector_default)
        db.commit()
    
    # Crear usuario admin si no existe
    admin = db.query(User).filter_by(username="admin").first()
    if not admin:
        hashed = bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()
        admin = User(username="admin",
                     hashed_password=hashed,
                     role_id=role_admin.id,
                     sector_id=sector_default.id)
        db.add(admin)
        db.commit()
    
    db.close()