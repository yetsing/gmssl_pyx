#!/usr/bin/env bash

# 构建 c 扩展脚本

# 激活本地的虚拟 Python 环境
if [[ -f "venv/bin/activate" ]] && [ "${VIRTUAL_ENV}" == "" ]
then
  source venv/bin/activate
fi

set -ex

# 构建 c extension
python setup.py build_ext --inplace
