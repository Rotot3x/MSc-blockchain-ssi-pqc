"""Setup for pqc_didpeer4_fm plugin."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pqc_didpeer4_fm",
    version="0.1.0",
    author="Ferris Menzel",
    author_email="admin@example.com",
    description="Post-Quantum did:peer:4 plugin with ML-DSA-65 + ML-KEM-768 for ACA-Py",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=find_packages(),
    install_requires=[
        # Note: aries-cloudagent is NOT listed here because this plugin
        # runs inside an existing ACA-Py installation which provides all
        # core dependencies. Only list additional dependencies needed by
        # this plugin that are not part of standard ACA-Py.
        "did-peer-4>=0.1.4",
        "pydid>=0.4.0",
        "multiformats>=0.3.0",
        "base58>=2.1.0",
        "liboqs-python>=0.10.0",
    ],
    entry_points={
        "aries_cloudagent.plugins": [
            "pqc_didpeer4_fm = pqc_didpeer4_fm:setup"
        ]
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="pqc post-quantum cryptography did peer ml-dsa ml-kem acapy aries ssi",
)
