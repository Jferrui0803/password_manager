# test_password.py
from app.services.password_service import PasswordService

svc = PasswordService()

# Añadir una entrada de ejemplo
entry = svc.add_entry(
    title="Servidor FTP",
    username="ftp_user",
    plaintext_password="MiPassSecreta!",
    sector_name="IT"
)
print("Entry creada ID:", entry.id)

# Listar todas
all_entries = svc.list_entries()
print("Total entradas:", len(all_entries))

# Obtener y desencriptar
e = svc.get_entry(entry.id)
print("Datos desencriptados:", e.title, e.username, e.password)

# Actualizar contraseña
updated = svc.update_entry(entry.id, plaintext_password="NuevaPass123")
print("Contraseña actualizada:", svc.get_entry(entry.id).password)

# Borrar entrada
svc.delete_entry(entry.id)
print("Después de borrar, total:", len(svc.list_entries()))
