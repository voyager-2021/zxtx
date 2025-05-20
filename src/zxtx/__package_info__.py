import toml

with open("pyproject.toml", "r") as file:
    pyproject = toml.load(file)

__version__ = "0.1.0"
__project_name__ = pyproject["project"]["name"]
__author__ = pyproject["project"]["authors"][0]["name"]
__email__ = pyproject["project"]["authors"][0]["email"]
__license__ = pyproject["project"]["license"]["text"]
__url__ = pyproject["project"]["urls"]["Homepage"]
__documentation__ = pyproject["project"]["urls"]["Documentation"]
__repository__ = pyproject["project"]["urls"]["Source"]
__issues__ = pyproject["project"]["urls"]["Issues"]
__description__ = pyproject["project"]["description"]
__readme__ = pyproject["project"]["readme"]
__keywords__ = pyproject["project"]["keywords"]
__dependencies__ = pyproject["project"]["dependencies"]
__dev_dependencies__ = pyproject["project"]["optional-dependencies"]["dev"]
__python_requires__ = pyproject["project"]["requires-python"]
__classifiers__ = pyproject["project"]["classifiers"]
__build_backend__ = pyproject["build-system"]["build-backend"]
__build_requires__ = pyproject["build-system"]["requires"]

__all__ = [
    "__version__",
    "__project_name__",
    "__author__",
    "__email__",
    "__license__",
    "__url__",
    "__documentation__",
    "__repository__",
    "__issues__",
    "__description__",
    "__readme__",
    "__keywords__",
    "__dependencies__",
    "__dev_dependencies__",
    "__python_requires__",
    "__classifiers__",
    "__build_backend__",
    "__build_requires__",
]
