from setuptools import setup, find_packages

setup(
    name="pysandboxing",  # Name of your package
    version="0.1.2",  # Initial version
    packages=find_packages(),  # Automatically finds all packages in the directory
    install_requires=[],  # List of dependencies (if any)
    author="Libardo Ramirez Tirado",  # Replace with your name
    author_email="libar@libardoramirez.com",  # Replace with your email
    description="A Python module for sandboxing code with restricted imports and timeout enforcement (Linux/macOS only)",  # Short description
    long_description=open("README.md").read(),  # Read long description from README file (if available)
    long_description_content_type="text/markdown",  # Markup type for the long description (adjust if needed)
    url="https://github.com/libardoram/pysandboxing",  # Replace with your project's URL or repository
    classifiers=[  # Classifiers help categorize your package
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.6",  # Minimum Python version required
    keywords="sandboxing security",  # Keywords to help people find your package
    
)