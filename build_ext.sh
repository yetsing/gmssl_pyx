#!/usr/bin/env bash

source venv/bin/activate
python setup.py build_ext --build-lib=gmssl_pyx
