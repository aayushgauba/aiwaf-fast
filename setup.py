"""
AIWAF - AI Web Application Firewall for FastAPI
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="aiwaf-fast",
    version="1.0.0",
    author="AIWAF Team",
    author_email="contact@aiwaf.com",
    description="AI Web Application Firewall for FastAPI - Advanced security middleware",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aiwaf/aiwaf-fastapi",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8", 
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: FastAPI",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.7",
    install_requires=[
        "fastapi>=0.68.0",
        "starlette>=0.14.0",
        "pydantic>=1.8.0",
    ],
    extras_require={
        "dev": [
            "uvicorn[standard]>=0.15.0",
            "pytest>=6.0",
            "pytest-asyncio>=0.18.0",
            "httpx>=0.23.0",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.950",
        ],
        "docs": [
            "mkdocs>=1.4.0",
            "mkdocs-material>=8.0.0",
            "mkdocstrings[python]>=0.18.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "aiwaf=aiwaf.cli:main",
        ],
    },
    keywords="fastapi security middleware firewall bot-detection rate-limiting",
    project_urls={
        "Bug Reports": "https://github.com/aiwaf/aiwaf-fastapi/issues",
        "Source": "https://github.com/aiwaf/aiwaf-fastapi",
        "Documentation": "https://aiwaf-fastapi.readthedocs.io/",
    },
    include_package_data=True,
    zip_safe=False,
)