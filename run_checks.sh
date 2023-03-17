#!/bin/bash

set -e

echo "CI is set to [${CI}]"
if [[ $CI != "true" ]]; then
    pre-commit run --all-files
fi

echo "Running $(mypy --version)"
mypy

echo "Running unit tests $(python -V)"
python -m unittest
