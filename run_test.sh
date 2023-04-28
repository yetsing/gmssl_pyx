#!/usr/bin/env bash

set -ex

source venv/bin/activate

python -m unittest discover tests
