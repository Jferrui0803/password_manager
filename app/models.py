# app/models.py
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime

class Role(Base):
    __tablename__ = "roles"

    id   = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    users = relationship("User", back_populates="role")


class Sector(Base):
    __tablename__ = "sectors"

    id   = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    users     = relationship("User", back_populates="sector")
    passwords = relationship("PasswordEntry", back_populates="sector")


class User(Base):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    verified        = Column(Boolean, default=False)

    role_id   = Column(Integer, ForeignKey("roles.id"), nullable=False)
    sector_id = Column(Integer, ForeignKey("sectors.id"), nullable=True)  

    role   = relationship("Role",   back_populates="users")
    sector = relationship("Sector", back_populates="users")


class PasswordEntry(Base):
    __tablename__ = "passwords"

    id                 = Column(Integer, primary_key=True, index=True)
    title              = Column(String, nullable=False)      
    username           = Column(String, nullable=False)      
    encrypted_password = Column(String, nullable=False)             
    created_at         = Column(DateTime, default=datetime.utcnow)
    sector_id          = Column(Integer, ForeignKey("sectors.id"), nullable=True)
    created_by         = Column(String, nullable=False) 

    sector = relationship("Sector", back_populates="passwords")