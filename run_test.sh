#!/usr/bin/env bash

# 运行项目的所有测试

# 激活本地的虚拟 Python 环境
if [[ -f "venv/bin/activate" ]] && [ "${VIRTUAL_ENV}" == "" ]
then
  source venv/bin/activate
fi

set -ex

# 运行测试
#python -m unittest discover -v tests
python test.py
python run_example.py
