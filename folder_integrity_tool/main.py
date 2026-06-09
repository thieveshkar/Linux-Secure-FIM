# Developed by: thieveshkar_cb013248
#
# Main entry point for the File Integrity Monitor.
# Initializes system checks and launches the CustomTkinter GUI.

# Import a function to check if the user has the required admin (root) privileges
from core.utils import check_root_privileges

# Import the main graphical user interface (GUI) application window
from gui.app import FIMConsole

# Define the main function where the program starts executing
def main():
    # Security Rule 1: Validate system privileges before executing the integrity monitor.
    # We call the function to ensure the user is running the program as an administrator
    # This is important because monitoring core files requires high-level access
    check_root_privileges()
    
    # Initialize and run the redesigned GUI
    # Create an instance of our main application window
    app = FIMConsole()
    
    # Start the application's event loop, which keeps the window open and responsive to user actions
    app.mainloop()

# Check if this script is being run directly (and not imported as a module by another script)
if __name__ == "__main__":
    # If it is run directly, call the main() function to start the application
    main()
6
