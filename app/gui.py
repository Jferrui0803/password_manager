import tkinter as tk
from tkinter import messagebox, ttk
import tkinter.simpledialog as simpledialog  
from app.services.auth_service import AuthService
from app.services.password_service import PasswordService
from app.models import Sector

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("900x650")
        # Configuración de estilos para un aspecto más moderno
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TLabel', font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), padding=6)
        self.style.configure('TEntry', font=('Segoe UI', 10))
        self.style.configure('Treeview', font=('Segoe UI', 10), rowheight=28)
        self.style.configure('Treeview.Heading', font=('Segoe UI', 11, 'bold'), background='#4A90E2', foreground='white')

        self.auth_service = AuthService()
        self.pw_service = PasswordService()
        self.current_user = None
        self.login_frame()

    def login_frame(self):
        self.clear_frame()
        container = ttk.Frame(self.root, padding=30)
        container.pack(expand=True)
        
        try:
            self.logo = tk.PhotoImage(file="img\\kyndryl-logo.png")
            ttk.Label(container, image=self.logo).grid(row=0, column=0, columnspan=2, pady=(0,15))
        except Exception as e:
            print("No se pudo cargar la imagen:", e)

        ttk.Label(container, text="Iniciar Sesión", font=('Segoe UI', 14, 'bold')).grid(row=1, column=0, columnspan=2, pady=(5,15))
        
        ttk.Label(container, text="Usuario:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(container, textvariable=self.username_var, width=30).grid(row=2, column=1, pady=5)

        ttk.Label(container, text="Contraseña:").grid(row=3, column=0, sticky="e", padx=5, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(container, textvariable=self.password_var, show="*", width=30)
        self.password_entry.grid(row=3, column=1, pady=5)
    
        self.show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(container, text="Mostrar contraseña", variable=self.show_password_var, command=self.toggle_password).grid(row=4, column=1, sticky="w", pady=5)

        ttk.Button(container, text="Login", command=self.handle_login).grid(row=5, column=0, columnspan=2, pady=20)
        ttk.Button(container, text="Crear Usuario", command=self.create_user_window).grid(row=6, column=0, columnspan=2, pady=10)

    def toggle_password(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def create_user_window(self):
        win = tk.Toplevel(self.root)
        win.title("Crear Usuario")
        win.transient(self.root)
        win.grab_set()

        ttk.Label(win, text="Usuario:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        username_var = tk.StringVar()
        ttk.Entry(win, textvariable=username_var, width=30).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(win, text="Contraseña:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        password_var = tk.StringVar()
        ttk.Entry(win, textvariable=password_var, width=30, show="*").grid(row=1, column=1, padx=5, pady=5)

        # No se muestra campo de Departamento para registro de usuarios comunes.
        
        def create_user():
            username = username_var.get().strip()
            password = password_var.get().strip()
            if not username or not password:
                messagebox.showwarning("Atención", "Todos los campos son requeridos")
                return
            try:
                # Pasamos "" para sector_name (o could pass None) para que no se asigne ningún departamento.
                self.auth_service.register_user(username, password, "user", "")
                messagebox.showinfo("Éxito", "Usuario creado exitosamente")
                win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))
                
        ttk.Button(win, text="Crear Usuario", command=create_user).grid(row=2, column=0, columnspan=2, pady=10)

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def handle_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        try:
            user = self.auth_service.authenticate(username, password)
            self.current_user = user
            self.main_frame()
        except Exception as e:
            messagebox.showerror("Error de Login", str(e))

    def main_frame(self):
        self.clear_frame()
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        # Barra superior (código existente)...
        header = ttk.Frame(self.root, padding=10)
        header.grid(row=0, column=0, sticky='ew')
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text=f"Bienvenido, {self.current_user.username}", font=('Segoe UI', 12, 'bold')).grid(row=0, column=0)
        ttk.Button(header, text="Logout", command=self.logout).grid(row=0, column=2)
        if self.current_user.role.name == "admin":
            ttk.Button(header, text="Panel de administrador", command=self.admin_panel_window).grid(row=0, column=3, padx=10)
            ttk.Button(header, text="Vista de usuarios", command=self.view_user_passwords).grid(row=0, column=4, padx=10)

        # Frame principal
        main = ttk.Frame(self.root, padding=(10,5))
        main.grid(row=1, column=0, sticky='nsew')
        main.columnconfigure(0, weight=0)
        main.columnconfigure(1, weight=1)
        # Configuramos dos filas: la de búsqueda (fila 0) y el listado (fila 1)
        main.rowconfigure(0, weight=0)
        main.rowconfigure(1, weight=1)

        # Fila de búsqueda con label
        search_label = ttk.Label(main, text="Escribe para buscar (título):")
        search_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(main, textvariable=search_var, width=25)  
        search_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        search_entry.bind("<KeyRelease>", lambda event: self.filter_entries(search_var.get()))

        # Lista de entradas (se coloca en fila 1)
        tree_frame = ttk.LabelFrame(main, text="Entradas de Contraseña:", padding=10)
        tree_frame.grid(row=1, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        cols = ("ID", "Título", "Usuario", "Contraseña", "Sector", "Creado")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode='browse')
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor='center')
        self.tree.grid(row=0, column=0, sticky='nsew')

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky='ns')

        # Botones de acción (código existente)
        btn_frame = ttk.Frame(main, padding=(5,10))
        btn_frame.grid(row=2, column=0, columnspan=2, sticky='ew')
        btn_frame.columnconfigure((0,1,2,3,4), weight=1)
        ttk.Button(btn_frame, text="Añadir", command=self.open_add).grid(row=0, column=0, padx=5, ipadx=10)
        ttk.Button(btn_frame, text="Editar", command=self.open_edit).grid(row=0, column=1, padx=5, ipadx=10)
        ttk.Button(btn_frame, text="Borrar", command=self.delete_entry).grid(row=0, column=2, padx=5, ipadx=10)
        ttk.Button(btn_frame, text="Mostrar Contraseña", command=self.show_password).grid(row=0, column=3, padx=5, ipadx=10)
        ttk.Button(btn_frame, text="Copiar Contraseña", command=self.copy_password).grid(row=0, column=4, padx=5, ipadx=10)

        self.refresh_entries()

    def refresh_entries(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        # Para el admin se muestran solo las entradas creadas por él.
        if self.current_user.role.name == "admin":
            entries = [e for e in self.pw_service.list_entries() if e.created_by == self.current_user.username]
        else:
            # Para usuarios comunes, se muestran solo las entradas creadas por ellos (ya que no tienen departamento asignado)
            entries = [e for e in self.pw_service.list_entries() if e.created_by == self.current_user.username]
        for e in entries:
            self.tree.insert("", "end", values=(
                e.id,
                e.title,
                e.username,
                "********",
                e.sector.name if e.sector else "",
                e.created_at.strftime("%Y-%m-%d %H:%M:%S")
            ))

    def filter_entries(self, search_text: str):
        # Clear current rows
        for i in self.tree.get_children():
            self.tree.delete(i)
        # Get entries (same filter by created_by for both admin and users)
        if self.current_user.role.name == "admin":
            entries = [e for e in self.pw_service.list_entries() if e.created_by == self.current_user.username]
        else:
            entries = [e for e in self.pw_service.list_entries() if e.created_by == self.current_user.username]
        # If search text is provided, filter by title (case-insensitive)
        if search_text:
            entries = [e for e in entries if search_text.lower() in e.title.lower()]
        for e in entries:
            self.tree.insert("", "end", values=(
                e.id,
                e.title,
                e.username,
                "********",
                e.sector.name if e.sector else "",
                e.created_at.strftime("%Y-%m-%d %H:%M:%S")
            ))            

    def copy_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona una entrada primero")
            return
        # Obtener la contraseña real (desencriptada)
        entry_id = self.tree.item(selected[0])["values"][0]
        entry = self.pw_service.get_entry(entry_id)
        self.root.clipboard_clear()
        self.root.clipboard_append(entry.password)
        messagebox.showinfo("Copiado", "La contraseña ha sido copiada al portapapeles")

    def admin_panel_window(self):
        from app.models import User, Role, Sector
        win = tk.Toplevel(self.root)
        win.title("Panel de administrador")
        win.transient(self.root)
        win.grab_set()

        notebook = ttk.Notebook(win)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # --- Pestaña de Usuarios ---
        users_frame = ttk.Frame(notebook)
        notebook.add(users_frame, text="Usuarios")
        
        user_tree = ttk.Treeview(users_frame, columns=("ID", "Usuario", "Rol", "Departamento"), show="headings", selectmode="browse")
        for col in ("ID", "Usuario", "Rol", "Departamento"):
            user_tree.heading(col, text=col)
            user_tree.column(col, anchor="center")
        user_tree.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        users_frame.rowconfigure(0, weight=1)
        users_frame.columnconfigure(0, weight=1)
        
        def load_users():
            for i in user_tree.get_children():
                user_tree.delete(i)
            users = self.auth_service.db.query(User).all()
            for u in users:
                user_tree.insert("", "end", values=(
                    u.id,
                    u.username,
                    u.role.name,
                    u.sector.name if u.sector else ""
                ))
        load_users()
        
        def create_user():
            create_win = tk.Toplevel(win)
            create_win.title("Crear Usuario")
            create_win.transient(win)
            create_win.grab_set()
            
            ttk.Label(create_win, text="Usuario:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
            username_var = tk.StringVar()
            ttk.Entry(create_win, textvariable=username_var, width=30).grid(row=0, column=1, padx=5, pady=5)
            
            ttk.Label(create_win, text="Contraseña:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
            password_var = tk.StringVar()
            ttk.Entry(create_win, textvariable=password_var, width=30, show="*").grid(row=1, column=1, padx=5, pady=5)
            
            ttk.Label(create_win, text="Rol:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
            roles = [r.name for r in self.auth_service.db.query(Role).all()]
            role_var = tk.StringVar(value="user")
            ttk.Combobox(create_win, textvariable=role_var, values=roles, state="readonly", width=28).grid(row=2, column=1, padx=5, pady=5)
            
            ttk.Label(create_win, text="Departamento:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
            sectors = [s.name for s in self.auth_service.db.query(Sector).all()]
            sector_var = tk.StringVar()
            ttk.Combobox(create_win, textvariable=sector_var, values=sectors, state="readonly", width=28).grid(row=3, column=1, padx=5, pady=5)
            
            def save_user():
                uname = username_var.get().strip()
                pwd = password_var.get().strip()
                role_sel = role_var.get().strip()
                sector_sel = sector_var.get().strip()
                if not uname or not pwd or not role_sel or not sector_sel:
                    messagebox.showwarning("Atención", "Todos los campos son requeridos")
                    return
                try:
                    self.auth_service.register_user(uname, pwd, role_sel, sector_sel)
                    messagebox.showinfo("Éxito", "Usuario creado exitosamente")
                    create_win.destroy()
                    load_users()
                except Exception as e:
                    messagebox.showerror("Error", str(e))
            ttk.Button(create_win, text="Crear Usuario", command=save_user).grid(row=4, column=0, columnspan=2, pady=10)
        
        def edit_user():
            selected = user_tree.selection()
            if not selected:
                messagebox.showwarning("Atención", "Selecciona un usuario")
                return
            user_id = user_tree.item(selected[0])["values"][0]
            user = self.auth_service.db.query(User).get(user_id)
            edit_win = tk.Toplevel(win)
            edit_win.title("Editar Usuario")
            edit_win.transient(win)
            edit_win.grab_set()
            
            ttk.Label(edit_win, text="Usuario:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
            username_var = tk.StringVar(value=user.username)
            ttk.Entry(edit_win, textvariable=username_var, width=30).grid(row=0, column=1, padx=5, pady=5)
            
            ttk.Label(edit_win, text="Nueva Contraseña:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
            password_var = tk.StringVar()
            ttk.Entry(edit_win, textvariable=password_var, width=30, show="*").grid(row=1, column=1, padx=5, pady=5)
            
            ttk.Label(edit_win, text="Rol:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
            roles = [r.name for r in self.auth_service.db.query(Role).all()]
            role_var = tk.StringVar(value=user.role.name)
            ttk.Combobox(edit_win, textvariable=role_var, values=roles, state="readonly", width=28).grid(row=2, column=1, padx=5, pady=5)
            
            ttk.Label(edit_win, text="Departamento:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
            sectors = [s.name for s in self.auth_service.db.query(Sector).all()]
            sector_var = tk.StringVar(value=user.sector.name)
            ttk.Combobox(edit_win, textvariable=sector_var, values=sectors, state="readonly", width=28).grid(row=3, column=1, padx=5, pady=5)
            
            def save_changes():
                new_username = username_var.get().strip()
                new_role = role_var.get().strip()
                new_sector = sector_var.get().strip()
                new_password = password_var.get().strip()
                if not new_username or not new_role or not new_sector:
                    messagebox.showwarning("Atención", "Usuario, Rol y Departamento son requeridos")
                    return
                user.username = new_username
                # Actualizar la contraseña solo si se ha ingresado un nuevo valor
                if new_password:
                    import bcrypt
                    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
                    user.hashed_password = hashed
                role_obj = self.auth_service.db.query(Role).filter_by(name=new_role).first()
                if not role_obj:
                    messagebox.showerror("Error", "Rol inválido")
                    return
                user.role_id = role_obj.id
                sector_obj = self.auth_service.db.query(Sector).filter_by(name=new_sector).first()
                if not sector_obj:
                    messagebox.showerror("Error", "Departamento inválido")
                    return
                user.sector_id = sector_obj.id
                self.auth_service.db.commit()
                self.auth_service.db.refresh(user)
                user_tree.item(selected[0], values=(user.id, user.username, user.role.name, user.sector.name))
                edit_win.destroy()
            
            ttk.Button(edit_win, text="Guardar", command=save_changes).grid(row=4, column=0, columnspan=2, pady=10)
        
        def delete_user():
            selected = user_tree.selection()
            if not selected:
                messagebox.showwarning("Atención", "Selecciona un usuario")
                return
            user_id = user_tree.item(selected[0])["values"][0]
            if user_id == self.current_user.id:
                messagebox.showerror("Error", "No puedes eliminarte a ti mismo")
                return
            if messagebox.askyesno("Confirmar", "¿Estás seguro de borrar este usuario?"):
                user = self.auth_service.db.query(User).get(user_id)
                self.auth_service.db.delete(user)
                self.auth_service.db.commit()
                user_tree.delete(selected[0])
        
        ttk.Button(users_frame, text="Crear Usuario", command=create_user).grid(row=1, column=0, padx=10, pady=10)
        ttk.Button(users_frame, text="Editar Usuario", command=edit_user).grid(row=1, column=1, padx=10, pady=10)
        ttk.Button(users_frame, text="Eliminar Usuario", command=delete_user).grid(row=1, column=2, padx=10, pady=10)
        
        # --- Pestaña de Departamentos ---
        dept_frame = ttk.Frame(notebook)
        notebook.add(dept_frame, text="Departamentos")
        
        dept_tree = ttk.Treeview(dept_frame, columns=("ID", "Nombre"), show="headings", selectmode="browse")
        for col in ("ID", "Nombre"):
            dept_tree.heading(col, text=col)
            dept_tree.column(col, anchor="center")
        dept_tree.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        dept_frame.rowconfigure(0, weight=1)
        dept_frame.columnconfigure(0, weight=1)
        
        def load_departments():
            for i in dept_tree.get_children():
                dept_tree.delete(i)
            depts = self.auth_service.db.query(Sector).all()
            for d in depts:
                dept_tree.insert("", "end", values=(d.id, d.name))
        load_departments()
        
        def create_department():
            create_dept_win = tk.Toplevel(win)
            create_dept_win.title("Crear Departamento")
            create_dept_win.transient(win)
            create_dept_win.grab_set()
            
            ttk.Label(create_dept_win, text="Nombre:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
            name_var = tk.StringVar()
            ttk.Entry(create_dept_win, textvariable=name_var, width=30).grid(row=0, column=1, padx=5, pady=5)
            
            def save_dept():
                name = name_var.get().strip()
                if not name:
                    messagebox.showwarning("Atención", "El nombre es requerido")
                    return
                if self.auth_service.db.query(Sector).filter_by(name=name).first():
                    messagebox.showerror("Error", "El departamento ya existe")
                    return
                new_dept = Sector(name=name)
                self.auth_service.db.add(new_dept)
                self.auth_service.db.commit()
                load_departments()
                create_dept_win.destroy()
            ttk.Button(create_dept_win, text="Crear Departamento", command=save_dept).grid(row=1, column=0, columnspan=2, pady=10)
        
        def edit_department():
            selected = dept_tree.selection()
            if not selected:
                messagebox.showwarning("Atención", "Selecciona un departamento")
                return
            dept_id = dept_tree.item(selected[0])["values"][0]
            dept = self.auth_service.db.query(Sector).get(dept_id)
            edit_dept_win = tk.Toplevel(win)
            edit_dept_win.title("Editar Departamento")
            edit_dept_win.transient(win)
            edit_dept_win.grab_set()
            
            ttk.Label(edit_dept_win, text="Nombre:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
            name_var = tk.StringVar(value=dept.name)
            ttk.Entry(edit_dept_win, textvariable=name_var, width=30).grid(row=0, column=1, padx=5, pady=5)
            
            def save_dept_changes():
                new_name = name_var.get().strip()
                if not new_name:
                    messagebox.showwarning("Atención", "El nombre es requerido")
                    return
                dept.name = new_name
                self.auth_service.db.commit()
                self.auth_service.db.refresh(dept)
                dept_tree.item(selected[0], values=(dept.id, dept.name))
                edit_dept_win.destroy()
            ttk.Button(edit_dept_win, text="Guardar", command=save_dept_changes).grid(row=1, column=0, columnspan=2, pady=10)
        
        def delete_department():
            selected = dept_tree.selection()
            if not selected:
                messagebox.showwarning("Atención", "Selecciona un departamento")
                return
            dept_id = dept_tree.item(selected[0])["values"][0]
            from app.models import User
            users_in_dept = self.auth_service.db.query(User).filter_by(sector_id=dept_id).count()
            if users_in_dept > 0:
                messagebox.showerror("Error", "No se puede eliminar un departamento con usuarios asociados")
                return
            dept = self.auth_service.db.query(Sector).get(dept_id)
            self.auth_service.db.delete(dept)
            self.auth_service.db.commit()
            dept_tree.delete(selected[0])
        
        ttk.Button(dept_frame, text="Crear Departamento", command=create_department).grid(row=1, column=0, padx=10, pady=10)
        ttk.Button(dept_frame, text="Editar Departamento", command=edit_department).grid(row=1, column=1, padx=10, pady=10)
        ttk.Button(dept_frame, text="Eliminar Departamento", command=delete_department).grid(row=1, column=2, padx=10, pady=10)
    

    def view_user_passwords(self):
        win = tk.Toplevel(self.root)
        win.title("Vista de usuarios")
        win.transient(self.root)
        win.grab_set()
        win.state('zoomed')

        # Search bar frame
        search_frame = ttk.Frame(win, padding=10)
        search_frame.grid(row=0, column=0, sticky="ew")
        search_frame.columnconfigure(1, weight=1)
        search_label = ttk.Label(search_frame, text="Buscar (título):")
        search_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=25)
        search_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # Treeview frame (below search bar)
        tree_frame = ttk.LabelFrame(win, text="Entradas de Contraseña de Usuarios", padding=10)
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        win.rowconfigure(1, weight=1)
        win.columnconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        cols = ("ID", "Creada por", "Título", "Usuario", "Contraseña", "Sector")
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, anchor="center")
        tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        def refresh_tree(search_text=""):
            for i in tree.get_children():
                tree.delete(i)
            entries = [e for e in self.pw_service.list_entries() if e.created_by != self.current_user.username]
            if search_text:
                entries = [e for e in entries if search_text.lower() in e.title.lower()]
            for e in entries:
                tree.insert("", "end", values=(
                    e.id,
                    e.created_by,
                    e.title,
                    e.username,
                    "********",
                    e.sector.name if e.sector else ""
                ))
        refresh_tree()
        search_entry.bind("<KeyRelease>", lambda event: refresh_tree(search_var.get()))

        # Botones de acción (editar, borrar y mostrar contraseña)
        # Se ha reducido el padding superior de 10 a 5 para subir los botones un poco
        btn_frame = ttk.Frame(win, padding=(5,30))
        btn_frame.grid(row=2, column=0, sticky="ew", pady=(5,30))
        for i in range(3):
            btn_frame.columnconfigure(i, weight=1)

        def edit_entry():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Atención", "Selecciona una entrada")
                return
            entry_id = tree.item(selected[0])["values"][0]
            entry = self.pw_service.get_entry(entry_id)
            self.entry_window_for_user(entry, lambda: refresh_tree(search_var.get()))

        def delete_entry():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Atención", "Selecciona una entrada")
                return
            entry_id = tree.item(selected[0])["values"][0]
            if messagebox.askyesno("Confirmar", "¿Está seguro de borrar esta entrada?"):
                self.pw_service.delete_entry(entry_id)
                tree.delete(selected[0])

        def toggle_password():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Atención", "Selecciona una entrada")
                return
            item = tree.item(selected[0])
            current_disp = item["values"][4]
            entry_id = item["values"][0]
            entry = self.pw_service.get_entry(entry_id)
            if current_disp == "********":
                new_disp = entry.password
                toggle_btn.config(text="Ocultar Contraseña")
            else:
                new_disp = "********"
                toggle_btn.config(text="Mostrar Contraseña")
            values = list(item["values"])
            values[4] = new_disp
            tree.item(selected[0], values=values)

        ttk.Button(btn_frame, text="Editar", command=edit_entry).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Borrar", command=delete_entry).grid(row=0, column=1, padx=5, pady=5)
        toggle_btn = ttk.Button(btn_frame, text="Mostrar Contraseña", command=toggle_password)
        toggle_btn.grid(row=0, column=2, padx=5, pady=5)

 
    def entry_window_for_user(self, entry, refresh_func):
        # Esta ventana es similar a entry_window, pero al finalizar llamará a refresh_func para actualizar la ventana de "Vista de usuarios"
        win = tk.Toplevel(self.root)
        win.title("Editar Entrada")
        win.transient(self.root)
        win.grab_set()
        fields = ["Título", "Usuario", "Contraseña", "Sector"]
        vars_ = {}
        default = {
            "Título": entry.title,
            "Usuario": entry.username,
            "Contraseña": entry.password,
            "Sector": entry.sector.name
        }
        for i, field in enumerate(fields):
            ttk.Label(win, text=f"{field}:").grid(row=i, column=0, sticky="e", padx=5, pady=5)
            var = tk.StringVar(value=default[field])
            if field == "Sector":
                combo = ttk.Combobox(win, textvariable=var,
                                     values=[s.name for s in self.auth_service.db.query(Sector).all()],
                                     state="readonly", width=28)
                combo.grid(row=i, column=1, pady=5)
            elif field == "Contraseña":
                ttk.Entry(win, textvariable=var, show="*", width=30).grid(row=i, column=1, pady=5)
            else:
                ttk.Entry(win, textvariable=var, width=30).grid(row=i, column=1, pady=5)
            vars_[field] = var
        
        def save():
            selected_sector = vars_["Sector"].get().strip()
            try:
                data = {
                    "title": vars_["Título"].get(),
                    "username": vars_["Usuario"].get(),
                    "plaintext_password": vars_["Contraseña"].get(),
                    "sector_name": selected_sector
                }
                self.pw_service.update_entry(entry.id, **data)
                win.destroy()
                refresh_func()
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        ttk.Button(win, text="Guardar", command=save).grid(row=len(fields), column=0, columnspan=2, pady=15)

    def reauthenticate(self):
        user_input = simpledialog.askstring("Reautenticación", "Usuario:", parent=self.root)
        if user_input is None:
            return None
        pwd_input = simpledialog.askstring("Reautenticación", "Contraseña:", show="*", parent=self.root)
        if pwd_input is None:
            return None
        try:
            validated = self.auth_service.authenticate(user_input, pwd_input)
            return validated
        except Exception:
            messagebox.showerror("Error", "Credenciales incorrectas")
            return None

    def show_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona una entrada primero")
            return
        # Solicitar reautenticación
        if not self.reauthenticate():
            return
        entry_id = self.tree.item(selected[0])["values"][0]
        entry = self.pw_service.get_entry(entry_id)
        # Para usuarios comunes, si tienen sector asignado se verifica que la entrada pertenezca a él.
        if self.current_user.role.name == "user" and self.current_user.sector and entry.sector:
            if entry.sector.name != self.current_user.sector.name:
                messagebox.showerror("Error", "No tiene permiso para ver la contraseña de este departamento")
                return
        # Actualizar la celda de la columna "Contraseña" (índice 3)
        vals = list(self.tree.item(selected[0])["values"])
        vals[3] = entry.password
        self.tree.item(selected[0], values=vals)

    def open_add(self):
        self.entry_window()

    def open_edit(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona una entrada primero")
            return
        entry_id = self.tree.item(selected[0])["values"][0]
        entry = self.pw_service.get_entry(entry_id)
        self.entry_window(entry)

    def entry_window(self, entry=None):
        win = tk.Toplevel(self.root)
        win.title("Editar Entrada" if entry else "Nueva Entrada")
        win.transient(self.root)
        win.grab_set()

        fields = ["Título", "Usuario", "Contraseña"]
        vars_ = {}
        default = {
            "Título": entry.title if entry else "",
            "Usuario": entry.username if entry else "",
            "Contraseña": entry.password if entry else ""
        }

        for i, field in enumerate(fields):
            ttk.Label(win, text=f"{field}:").grid(row=i, column=0, sticky='e', padx=5, pady=5)
            var = tk.StringVar(value=default[field])
            if field == "Contraseña":
                ttk.Entry(win, textvariable=var, show="*", width=30).grid(row=i, column=1, pady=5)
            else:
                ttk.Entry(win, textvariable=var, width=30).grid(row=i, column=1, pady=5)
            vars_[field] = var

        def save():
            try:
                # Si no hay sector asignado al usuario, se pasa cadena vacía.
                sector_name = self.current_user.sector.name if self.current_user.sector else ""
                data = {
                    "title": vars_["Título"].get(),
                    "username": vars_["Usuario"].get(),
                    "plaintext_password": vars_["Contraseña"].get(),
                    "sector_name": sector_name
                }
                if entry:
                    self.pw_service.update_entry(entry.id, **data)
                else:
                    self.pw_service.add_entry(**data, created_by=self.current_user.username)
                win.destroy()
                self.refresh_entries()
            except Exception as e:
                messagebox.showerror("Error", str(e))
        
        ttk.Button(win, text="Guardar", command=save).grid(row=len(fields), column=0, columnspan=2, pady=15)

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona una entrada")
            return
        entry_id = self.tree.item(selected[0])["values"][0]
        if messagebox.askyesno("Confirmar", "¿Estás seguro de borrar esta entrada?"):
            self.pw_service.delete_entry(entry_id)
            self.refresh_entries()

    def logout(self):
        self.current_user = None
        self.login_frame()


def launch_gui():
    root = tk.Tk()
    PasswordManagerGUI(root)
    root.mainloop()
