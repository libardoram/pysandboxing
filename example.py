import pysandboxing.sandbox as sandbox

import subprocess # This will fail

print("Example")

subprocess.run(["ls", "-l"])  # This will fail

while True:
    pass  # This will fail after 60 seconds