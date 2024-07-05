#!/bin/bash

set -xe

if [[ $1 == "clean" ]]; then
    echo "cleaning out .*cache/ directories"
    rm -rf .*cache/
fi

echo "CI is set to [${CI}]"
if [[ $CI != "true" ]]; then
    pre-commit run --all-files
fi

echo "Running $(mypy --version)"
mypy

echo "Running unit tests $(python -V)"
python -m unittest
