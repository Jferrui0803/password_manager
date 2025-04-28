# app/initial_data.py
from app.database import SessionLocal
from app.models import Role, Sector

def init_data():
    session = SessionLocal()
    # Roles por defecto
    for name in ["admin", "user"]:
        if not session.query(Role).filter_by(name=name).first():
            session.add(Role(name=name))

    # Sectores de ejemplo (ajusta a tu empresa)
    for name in ["IT", "HR", "Finance"]:
        if not session.query(Sector).filter_by(name=name).first():
            session.add(Sector(name=name))

    session.commit()
    session.close()
