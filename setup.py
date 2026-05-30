"""
LocalBridge - Selective MITM Proxy with SOCKS5

Setup configuration for package installation.
"""

from setuptools import setup, find_packages

setup(
    name="localbridge",
    version="0.1.0",
    description="Selective MITM Proxy with SOCKS5 - tunnel pinned, intercept non-pinned",
    author="LocalBridge Contributors",
    author_email="panda.soft.group@gmail.com",
    url="https://github.com/vhdrjb/Local-Bridge",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0.0",
        "pyyaml>=6.0",
        "loguru>=0.7.0",
    ],
    extras_require={
        "performance": ["uvloop>=0.17.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "localbridge=localbridge.main:run",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Proxy Servers",
    ],
)
