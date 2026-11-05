# PhishShift pipeline. Each stage reads only earlier outputs.
# See docs/2026-11-05-phishshift-implementation-plan.md for what each stage does.
# Recipes are single commands with no shell syntax so they run under cmd.exe and sh alike.

ifeq ($(OS),Windows_NT)
PYTHON ?= py -3.11
VENV_PY := .venv/Scripts/python.exe
else
PYTHON ?= python3.11
VENV_PY := .venv/bin/python
endif

STAGES := data timeline benign warehouse eda rq1 patterns radar inject explain policy freeze

.PHONY: setup test notebooks demo all $(STAGES)

setup:
	$(PYTHON) -m venv .venv
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -r requirements.txt

test:
	$(VENV_PY) -m pytest -q

# Phase 1 onward: each target is wired to scripts/run_*.py when its phase is built.
data timeline benign warehouse eda rq1 patterns radar inject explain policy freeze:
	@echo make $@: not implemented yet

demo:
	@echo make demo: not implemented yet (Phase 10)

notebooks:
	@echo make notebooks: not implemented yet (Phase 4)

all: $(STAGES)
