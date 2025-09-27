# setup.py
from setuptools import setup, find_packages

setup(
    name="hackmeharder",
    version="0.1.0",
    packages=find_packages(),
    # Explicitly include top-level Python modules so the CLI can find them
    py_modules=['cli', 'correlation_engine', 'SAST_check'],
    
    # List all project dependencies
    install_requires=[
        "click",
        "requests",
        "beautifulsoup4",
        "Flask",
        "PyYAML",
        "gunicorn"
    ],
    
    # Define the command-line script
    entry_points={
        "console_scripts": [
            "hackmeharder=cli:cli",
        ],
    },
)