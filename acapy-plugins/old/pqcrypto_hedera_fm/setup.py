"""Setup for PQCrypto Hedera FM Plugin."""

from setuptools import setup, find_packages

setup(
    name="pqcrypto_hedera_fm",
    version="1.0.0",
    description="Post-Quantum Cryptography plugin for ACA-Py with Hedera Hashgraph integration",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="PQC Research Team",
    author_email="research@pqc.example.com",
    url="https://github.com/pqc-research/pqcrypto-hedera-fm",
    license="Apache License 2.0",
    packages=find_packages(),
    python_requires=">=3.12",
    install_requires=[
        "aries-cloudagent>=0.10.0",
        "pqcrypto-fm>=1.0.0",  # Our base PQC plugin
        "cryptography>=41.0.0",
        "pyjwt>=2.8.0",
        "requests>=2.31.0",
        "aiohttp>=3.8.0",
        "base58>=2.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "liboqs": [
            "liboqs-python>=0.10.0",
        ],
    },
    entry_points={
        "aries_cloudagent.plugins": [
            "pqcrypto_hedera_fm = pqcrypto_hedera_fm:plugin_definition",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Distributed Computing",
    ],
    keywords="aries cloudagent aca-py hedera hashgraph post-quantum cryptography pqc ssi did verifiable-credentials",
    project_urls={
        "Bug Reports": "https://github.com/pqc-research/pqcrypto-hedera-fm/issues",
        "Source": "https://github.com/pqc-research/pqcrypto-hedera-fm",
        "Documentation": "https://pqcrypto-hedera-fm.readthedocs.io/",
    },
    zip_safe=False,
)