import builtins
import sys
import importlib.util
import signal
import logging
import os

# Configure logging to log to a file (e.g., 'blocked_imports.log')
logging.basicConfig(
    filename="pysandbox_blocked_imports.log", 
    level=logging.WARNING,  # Set to WARNING level to capture restricted imports
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Disable exec, eval, and open access to dangerous built-in functions
builtins.exec = None
builtins.eval = None
builtins.open = None

# Restrict modules
restricted_modules = {
    # OS & System-Level Access
    "os", "subprocess", "sys", "threading", "socket", "multiprocessing", "ctypes", "resource",

    # File & Directory Access
    "shutil", "pathlib", "tempfile",

    # Network & Internet Access
    "http", "http.client", "http.server", "urllib", "urllib.request", "urllib.response", "urllib.parse",
    "urllib.error", "urllib.robotparser", "ftplib", "smtplib", "poplib", "imaplib", "nntplib", "telnetlib",
    "asyncio", "select", "ssl",

    # Code Execution & Serialization Risks
    "pickle", "cPickle", "marshal", "shelve", "py_compile", "compileall", "zipimport",
    
    # Database & External Storage
    "sqlite3", "dbm", "anydbm", "dumbdbm", "whichdb", "bz2", "lzma", "zlib",
    
    # GUI & Input Control (if needed)
    "tkinter", "curses", "readline",
    
    # Debugging & Profiler (Prevent Inspection of the Running Process)
    "trace", "tracemalloc", "pdb", "cProfile",
}

class RestrictedImport:
    def __init__(self, original_import):
        self.original_import = original_import

    def find_spec(self, fullname, path, target=None):
        if fullname in restricted_modules:
            # Get the absolute file path of the script where the import is attempted
            file_path = os.path.abspath(sys.argv[0])  # Get the current script's absolute path
            # Log the attempted import with the full file path
            logging.warning(f"Attempted import of restricted module: {fullname} in file: {file_path}")
            return None
        return importlib.util.find_spec(fullname)

sys.meta_path.insert(0, RestrictedImport(__import__))

# -------------------------------
# TIMEOUT ENFORCEMENT (Linux/macOS)
# -------------------------------

TIMEOUT_SECONDS = int(os.getenv('PYSANDBOX_TIMEOUT', 60))  # Set timeout duration from environment or default to 60 seconds

def timeout_handler(signum, frame):
    """ Handler for forced termination on timeout. """
    logging.warning("Execution stopped due to possible infinite loop!")
    sys.exit(1)  # Forcefully exit the process

# Set the alarm timeout when the sandbox is imported
signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(TIMEOUT_SECONDS)