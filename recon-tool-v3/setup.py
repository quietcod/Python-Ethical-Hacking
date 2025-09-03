#!/usr/bin/env python3
"""
Setup Script for Recon Tool v3.0
Clean architecture installation
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="recon-tool-v3",
    version="3.0.0",
    author="quietcod",
    author_email="quietcod@example.com",
    description="Professional reconnaissance toolkit with clean architecture",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/quietcod/Python-Ethical-Hacking",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License", 
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0", 
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "advanced": [
            "psutil>=5.9.0",
            "python-nmap>=0.7.1",
            "dnspython>=2.4.0", 
            "cryptography>=41.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "recon-tool=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.json", "docs/*.md"],
    },
)
