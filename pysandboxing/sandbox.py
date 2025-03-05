import sys
import signal
import logging
import os
import inspect

# Configure logging to log to a file (e.g., 'blocked_imports.log')
logging.basicConfig(
    level=logging.WARNING,  # Set to WARNING level to capture restricted imports
    format="%(asctime)s - %(levelname)s - %(message)s"
)


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

class RestrictedImportFinder:
    def find_spec(self, fullname, path, target=None):
        if fullname in restricted_modules:
            # Get the caller's frame info
            caller_frame = inspect.currentframe().f_back
            calling_file = "unknown"
            
            # Walk up the stack to find the originating .py file
            while caller_frame:
                filename = caller_frame.f_code.co_filename
                if filename.endswith('.py') and not filename.endswith('sandbox.py'):
                    calling_file = os.path.abspath(filename)  # Get full path
                    break
                caller_frame = caller_frame.f_back
            
            logging.warning(f"Import of module '{fullname}' is restricted in file '{calling_file}'")
            sys.exit(1)
        return None  # Allow normal import process

# Insert our custom finder at the beginning of the import system
sys.meta_path.insert(0, RestrictedImportFinder())

TIMEOUT_SECONDS = int(os.getenv('PYSANDBOX_TIMEOUT', 6))  # Set timeout duration from environment or default to 60 seconds

def timeout_handler(signum, frame):
    """ Handler for forced termination on timeout. """
    # Get the caller's frame info
    caller_frame = frame
    calling_file = "unknown"
    
    # Walk up the stack to find the originating .py file
    while caller_frame:
        filename = caller_frame.f_code.co_filename
        if filename.endswith('.py') and not filename.endswith('sandbox.py'):
            calling_file = os.path.abspath(filename)  # Get full path
            break
        caller_frame = caller_frame.f_back
    
    logging.warning(f"Execution stopped due to possible infinite loop in {calling_file}!")
    sys.exit(1)  # Forcefully exit the process

# Set the alarm timeout when the sandbox is imported
signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(TIMEOUT_SECONDS)