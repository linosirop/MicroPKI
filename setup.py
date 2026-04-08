from setuptools import setup, find_packages

setup(
    name="micropki",
    version="0.1.0",
    description="Minimal PKI project for Sprint 1",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.4",
        "pytest>=7.0",
    ],
    entry_points={
        "console_scripts": [
            "micropki=micropki.cli:main",
        ],
    },
)