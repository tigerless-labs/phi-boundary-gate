.PHONY: install test release-tests lint build check ci

install:
	python3 -m pip install -e ".[dev]"

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

release-tests:
	python3 -m unittest discover -s .github/scripts/tests -v

lint:
	ruff check src tests .github/scripts

build:
	python3 -m build

check:
	python3 -m twine check dist/*

ci: lint test release-tests build check
