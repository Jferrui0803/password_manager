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
    
    # Crear sector "Administracion" exclusivo para admin
    sector_admin = db.query(Sector).filter_by(name="Administracion").first()
    if not sector_admin:
        sector_admin = Sector(name="Administracion")
        db.add(sector_admin)
        db.commit()

    # Crear otros sectores (ejemplo)
    for sec_name in ["RRHH", "Finanzas", "Marketing", "Ventas", "IT", "Ciberseguridad"]:
        if not db.query(Sector).filter_by(name=sec_name).first():
            db.add(Sector(name=sec_name))
    db.commit()
    
    # Crear usuario admin si no existe, asignándolo al sector "Administracion"
    admin = db.query(User).filter_by(username="admin").first()
    if not admin:
        hashed = bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()
        admin = User(username="admin",
                     hashed_password=hashed,
                     role_id=role_admin.id,
                     sector_id=sector_admin.id)
        db.add(admin)
        db.commit()
    
    db.close()