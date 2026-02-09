#!/bin/bash

set -xe

if [[ -d .venv/bin ]]; then
    export PATH=.venv/bin:$PATH
fi

echo "CI is set to [${CI}]"
if [[ $CI != "true" ]]; then
    pre-commit run --all-files
fi

ty --version
ty check

echo "Running unit tests $(python -VV)"
python -m unittest
