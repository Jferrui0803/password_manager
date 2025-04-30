# main.py
from app.database import init_db
from app.initial_data import init_data
from app.gui import launch_gui 
 
def main():
    init_db()
    init_data()
    launch_gui()

if __name__ == "__main__":
    main()
 