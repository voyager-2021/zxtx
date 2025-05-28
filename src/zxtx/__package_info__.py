__version__ = "0.1.1"  # Dynamic version number (major.minor.patch)

__project_name__ = "zxtx"
__author__ = "voyager-2021"
__email__ = "voyager-2019@outlook.com"
__license__ = "MIT"
__url__ = "https://github.com/voyager-2021/zxtx"
__documentation__ = "https://github.com/voyager-2021/zxtx#readme"
__repository__ = "https://github.com/voyager-2021/zxtx"
__issues__ = "https://github.com/voyager-2021/zxtx/issues"
__description__ = "ZXTX file format support."
__readme__ = "README.md"
__keywords__ = ["compression", "encryption", "file-format", "zxtx", "cryptography"]
__dependencies__ = [
    "cryptography>=45.0.1",
    "brotli>=1.1.0",
    "toml>=0.10.2",
]
__dev_dependencies__ = [
    "pytest>=8.3.5",
    "black>=25.1.0",
    "mypy>=1.15.0",
    "isort>=6.0.1",
    "pydocstyle>=6.3.0",
    "pylint>=3.3.7",
    "bandit>=1.8.3",
    "safety>=3.5.1",
    "flake8>=7.2.0",
    "tox>=4.26.0",
    "types-toml>=0.10.8.20240310",
    "coverage>=7.8.1",
    "pytest-cov>=6.1.1",
    "pre-commit>=4.2.0",
]
__python_requires__ = ">=3.10"
__classifiers__ = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security :: Cryptography",
    "Topic :: File Formats",
]
__build_backend__ = "pdm.backend"
__build_requires__ = ["pdm-backend"]
