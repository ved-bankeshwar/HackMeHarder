from setuptools import setup, find_packages

setup(
    name="hackmeharder",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "click",
        # add other dependencies
    ],
    entry_points={
        "console_scripts": [
            "hackmeharder=cli:cli",  # maps terminal command 'hackmeharder' to cli.py's cli() function
        ],
    },
)
