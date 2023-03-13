#!/bin/bash

set -e

if [[ ! -z $RUN_CHECKS_DOCKER ]]; then
    pip install --target=/tmp/.pip --upgrade --upgrade-strategy eager -r requirements-dev.txt
    PATH=/tmp/.pip/bin:$PATH
    PYTHONPATH=/tmp/.pip:$PYTHONPATH
    RUFF_CACHE_DIR=/tmp/.ruff_cache
    export PATH
    export PYTHONPATH
    export RUFF_CACHE_DIR
fi

echo "Running $(ruff --version)"
ruff check .

echo "Running $(black --version)"
black --check .

echo "Running $(mypy --version)"
mypy

echo "Running unit tests $(python -V)"
python -m unittest
