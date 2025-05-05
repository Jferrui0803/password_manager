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

    role_superadmin = db.query(Role).filter_by(name="superadmin").first()
    if not role_superadmin:
        role_superadmin = Role(name="superadmin")
        db.add(role_superadmin)
    db.commit()
    
    # Crear sector "Administracion" exclusivo para admin
    sector_admin = db.query(Sector).filter_by(name="Administrador").first()
    if not sector_admin:
        sector_admin = Sector(name="Administrador")
        db.add(sector_admin)
        db.commit()


    # Crear sector "Superadmin" exclusivo para superadmin
    sector_superadmin = db.query(Sector).filter_by(name="SuperAdministrador").first()
    if not sector_superadmin:
        sector_superadmin = Sector(name="SuperAdministrador")
        db.add(sector_superadmin)
        db.commit()

    # Crear otros sectores (ejemplo)
    additional_departments = ["RRHH", "Finanzas", "Marketing", "Ventas", "IT", "Ciberseguridad"]
    for sec_name in additional_departments:
        if not db.query(Sector).filter_by(name=sec_name).first():
            db.add(Sector(name=sec_name))
    db.commit()
    
    # Crear un admin para cada departamento adicional
    for dept in additional_departments:
        admin_username = f"{dept}_Admin"
        if not db.query(User).filter_by(username=admin_username).first():
            hashed = bcrypt.hashpw(admin_username.encode(), bcrypt.gensalt()).decode()
            sector = db.query(Sector).filter_by(name=dept).first()
            new_admin = User(
                username=admin_username,
                hashed_password=hashed,
                role_id=role_admin.id,
                sector_id=sector.id if sector else None
            )
            db.add(new_admin)
    db.commit()
    
    # Crear usuario superadmin y admin (ya existentes)
    superadmin = db.query(User).filter_by(username="superadmin").first()
    if not superadmin:
        hashed = bcrypt.hashpw("superadmin".encode(), bcrypt.gensalt()).decode()
        superadmin = User(
            username="superadmin",
            hashed_password=hashed,
            role_id=role_superadmin.id,
            sector_id=sector_superadmin.id
        )
        db.add(superadmin)
        db.commit()
    
    admin = db.query(User).filter_by(username="admin").first()
    if not admin:
        hashed = bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()
        admin = User(
            username="admin",
            hashed_password=hashed,
            role_id=role_admin.id,
            sector_id=sector_admin.id
        )
        db.add(admin)
        db.commit()

    
    db.close()