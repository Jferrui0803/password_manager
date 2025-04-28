# test_auth.py
from app.services.auth_service import AuthService

auth = AuthService()

# Registrar un admin
try:
    admin = auth.register_user("admin", "AdminPass123", "admin", "IT")
    print("Admin creado:", admin.username)
except Exception as e:
    print("Error al crear admin:", e)

# Intentar login
try:
    user = auth.authenticate("admin", "AdminPass123")
    print("Autenticado:", user.username, "con rol", user.role.name)
    auth.require_admin(user)
    print("Es administrador ✔")
except Exception as e:
    print("Error de autenticación:", e)
