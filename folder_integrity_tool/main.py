# Developed by: thieveshkar_cb013248
#
# Main entry point for the File Integrity Monitor.
# Initializes system checks and launches the CustomTkinter GUI.

from core.utils import check_root_privileges
from gui.app import FIMConsole

def main():
    # Security Rule 1: Validate system privileges before executing the integrity monitor.
    check_root_privileges()
    
    # Initialize and run the redesigned GUI
    app = FIMConsole()
    app.mainloop()

if __name__ == "__main__":
    main()
6