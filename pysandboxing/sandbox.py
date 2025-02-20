import builtins
import sys
import importlib.util
import signal
import logging
import os
from importlib.abc import MetaPathFinder, Loader

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

class RestrictedLoader(Loader):
    def __init__(self, fullname, path):
        self.fullname = fullname
        self.path = path

class RestrictedImportFinder(MetaPathFinder):
    def __init__(self, allowed_modules=None):
        self.allowed_modules = allowed_modules or ['builtins']
        
    def find_spec(self, fullname, path, target=None):
        # Check if module is allowed
        if any(fullname.startswith(allowed) for allowed in self.allowed_modules):
            # Use original spec finding mechanism but avoid recursive calls
            if not hasattr(sys.modules.get(fullname, None), '__spec__'):
                spec = self._original_find_spec(fullname, path)
                return spec
        return None
    
    def _original_find_spec(self, fullname, path):
        """Helper method to find spec without causing recursion"""
        # Temporarily remove self from meta_path to avoid recursion
        sys.meta_path.remove(self)
        try:
            spec = importlib.util.find_spec(fullname)
        finally:
            # Restore self to meta_path
            sys.meta_path.insert(0, self)
        return spec

sys.meta_path.insert(0, RestrictedImportFinder())

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