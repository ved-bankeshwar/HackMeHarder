
from setuptools import setup, find_packages


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hackmeharder",  
    version="0.1.0",  
    author="Ved, Alisha, Manan & Purvi",
    author_email="ved.bankeshwar@gmail.com",
    description="A correlated SAST and DAST scanner for web applications.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ved-bankeshwar/HackMeHarder",
    
  
    packages=find_packages(),
    
 
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
    

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
    ],
    python_requires='>=3.8',
)