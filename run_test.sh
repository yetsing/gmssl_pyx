#!/usr/bin/env bash

set -ex

if [[ -f "venv/bin/activate" ]]
then
  source venv/bin/activate
fi

python -m unittest discover tests
