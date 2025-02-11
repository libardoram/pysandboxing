# PySandboxing

PySandboxing is a Python module for sandboxing code with restricted imports and timeout enforcement. It prevents the execution of dangerous built-in functions and restricts the import of certain modules to enhance security. Sort of...


## Installation

### From PyPI

```sh
pip install pysandboxing
```

### From Source

To install PySandboxing, clone the repository and run the setup script:

```sh
git clone https://github.com/libardoram/pysandboxing.git
cd pysandboxing
python setup.py install
```

## Example Usage

To use `pysandboxing` in your Python code, simply import the module at the beginning of your script:

```python
import pysandboxing.sandbox  

while True:
 print("This will be stopped after the timeout!")
```


```python
import pysandboxing.sandbox as sandbox

import subprocess

subprocess.run(["ls", "-l"])

```

## Features

1. Disables dangerous built-in functions (exec, eval, open).
2. Restricts the import of certain modules to prevent security risks.
3. Enforces a timeout to stop possible infinite loops.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Author
Libardo Ramirez Tirado - libar@libardoramirez.com


