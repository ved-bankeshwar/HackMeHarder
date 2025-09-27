# setup.py
from setuptools import setup, find_packages

setup(
    name="hackmeharder",
    version="0.1",
    packages=find_packages(),
    # Explicitly tell setuptools to include top-level Python modules
    py_modules=['cli', 'correlation_engine', 'SAST_check'],
    install_requires=[
        "click",
        "requests",
        "beautifulsoup4",
        "Flask",
        "PyYAML",
        "gunicorn"
    ],
    entry_points={
        "console_scripts": [
            "hackmeharder=cli:cli",
        ],
    },
)