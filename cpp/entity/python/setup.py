"""SST Python API package."""

from setuptools import setup, find_packages

setup(
    name="sst-api",
    version="0.1.0",
    description="SST Python API for entity server and file system manager",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.9.0",
    ],
    extras_require={
        "dev": [
            "pytest",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)