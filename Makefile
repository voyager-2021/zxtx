.PHONY: all sync sync-dev sync-all install install-dev install-opt remake-venv test format build publish tox precommit precommit-update clean _clean_wrapper rebase-interactive log delete-branch-remote push-upstream rebase-push stash-apply stash-pop check-dirty

ifneq ($(OS),Windows_NT)
export $(shell cat .env 2>/dev/null | xargs)
endif

all: build

sync:
	@uv sync

sync-dev:
	@uv sync --dev

sync-all:
	@uv sync --all-extras --all-groups

install:
	@uv pip install .

install-dev:
	@uv pip install .[dev]

install-opt:
	@uv pip install .[opt]

remake-venv:
	@uv venv --clear -p 3.14
	@. .venv/bin/activate

test:
	@uv run coverage run -m pytest -m "not slow"
	@uv run coverage report
	@uv run coverage html
	@uv run coverage xml

tox:
	@uv run tox

lint:
	@uv run ruff check src tests
	@uv run mypy src tests

format:
	@uv run black src tests
	@uv run isort src tests --profile black
	@uv run ruff format

precommit:
	@$(MAKE) _precommit_wrapper -iks

_precommit_wrapper:
	@uv run pre-commit run --all-files

precommit-update:
	@uv run pre-commit autoupdate --repo https://github.com/pre-commit/pre-commit-hooks

clean:
	@$(MAKE) _clean_wrapper -iks

_clean_wrapper:
	rm -r src/zxtx/__pycache__
	rm -r tests/__pycache__
	rm -r dist/
	rm -r build/
	rm -r coverage.xml
	rm -r htmlcov/
	rm -r .coverage
	rm -r .pytest_cache/
	rm -r .mypy_cache/
	rm -r .ruff_cache/

rebase-interactive:
	@git fetch origin main
	@git rebase -i --autosquash origin/main

log:
	@git log --graph --pretty=format:'%C(auto)%h %ad %s %d [%an]' --date=short -20

delete-branch-remote:
ifdef BRANCH
	@git push origin --delete $(BRANCH)
else
	$(error BRANCH variable is required, e.g. make delete-branch-remote BRANCH=feature)
endif

push-upstream:
	@git push -u origin $$(git rev-parse --abbrev-ref HEAD)

rebase-push:
	@git push --force-with-lease

stash-apply:
	@git stash apply

stash-pop:
	@git stash pop

check-dirty:
ifneq ($(OS),Windows_NT)
	@if ! git diff-index --quiet HEAD --; then \
		$(error Uncommitted changes present, please commit or stash); \
	fi
else
	$(error This command is not supported on Windows)
endif
