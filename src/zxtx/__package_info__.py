__version__ = "0.1.0"  # Always hardcode or inject this during build

# Sensible defaults
__project_name__ = "Undefined"
__author__ = "Undefined"
__email__ = "Undefined"
__license__ = "Undefined"
__url__ = "Undefined"
__documentation__ = "Undefined"
__repository__ = "Undefined"
__issues__ = "Undefined"
__description__ = "Undefined"
__readme__ = "Undefined"
__keywords__ = []
__dependencies__ = []
__dev_dependencies__ = []
__python_requires__ = "Undefined"
__classifiers__ = []
__build_backend__ = "Undefined"
__build_requires__ = []

try:
    import toml
    from pathlib import Path

    current = Path(__file__).resolve().parent
    while current != current.parent:
        pyproject_path = current / "pyproject.toml"
        if pyproject_path.exists():
            break
        current = current.parent
    else:
        raise FileNotFoundError("pyproject.toml not found")

    pyproject = toml.load(pyproject_path)

    project = pyproject.get("project", {})
    __project_name__ = project.get("name", __project_name__)
    authors = project.get("authors", [{}])
    __author__ = authors[0].get("name", __author__)
    __email__ = authors[0].get("email", __email__)
    __license__ = project.get("license", {}).get("text", __license__)
    urls = project.get("urls", {})
    __url__ = urls.get("Homepage", __url__)
    __documentation__ = urls.get("Documentation", __documentation__)
    __repository__ = urls.get("Source", __repository__)
    __issues__ = urls.get("Issues", __issues__)
    __description__ = project.get("description", __description__)
    __readme__ = project.get("readme", __readme__)
    __keywords__ = project.get("keywords", __keywords__)
    __dependencies__ = project.get("dependencies", __dependencies__)
    __dev_dependencies__ = project.get("optional-dependencies", {}).get("dev", __dev_dependencies__)
    __python_requires__ = project.get("requires-python", __python_requires__)
    __classifiers__ = project.get("classifiers", __classifiers__)
    build_system = pyproject.get("build-system", {})
    __build_backend__ = build_system.get("build-backend", __build_backend__)
    __build_requires__ = build_system.get("requires", __build_requires__)
except Exception:
    pass  # Keep defaults

