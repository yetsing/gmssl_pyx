#!/usr/bin/env python3
import os
import urllib.request
import shutil
import subprocess
import tarfile

from setuptools.command.build_ext import build_ext
from distutils.core import setup, Extension


def download_source_code():
    if os.path.exists("GmSSL-3.1.0"):
        return
    source_path = "gmssl.tar.gz"
    if not os.path.exists(source_path):
        source_url = "https://github.com/guanzhi/GmSSL/archive/refs/tags/v3.1.0.tar.gz"
        urllib.request.urlretrieve(source_url, source_path)
    # 解压到当前文件夹
    with tarfile.open(source_path) as tar:
        tar.extractall()


def compile_gmssl():
    # 静态库存在就不编译了，节约时间
    if os.path.exists("GmSSL-3.1.0/build/bin/libgmssl.a"):
        return
    cwd = os.getcwd()
    # 下载 GmSSL 库编译成静态库
    # 1.下载源码并解压
    download_source_code()

    # 2. 修改 CMakeLists.txt ，直接编译会报错
    # /usr/bin/ld: ./GmSSL-3.1.0/build/bin/libgmssl.a(sm2_key.c.o): relocation R_X86_64_PC32 against symbol `stderr@@GLIBC_2.2.5' can not be used when making a shared object; recompile with -fPIC
    cmake_filename = "GmSSL-3.1.0/CMakeLists.txt"
    append_text = "add_compile_options(-fPIC)"
    with open(cmake_filename, "r") as f:
        text = f.read()
    if append_text not in text:
        # 根据错误说明增加编译选项 -fPIC ，加在 "project(GmSSL)" 后面
        sign = "project(GmSSL)"
        append_pos = text.find(sign) + len(sign)
        new_text = "".join(
            [
                text[:append_pos],
                "\n\n{}\n\n".format(append_text),
                text[append_pos:],
            ]
        )
        with open("GmSSL-3.1.0/CMakeLists.txt", "w") as f:
            f.write(new_text)

    # 3.编译静态库
    build_dir = "GmSSL-3.1.0/build"
    if os.path.exists(build_dir):
        # 删除之前的构建，重新生成
        shutil.rmtree(build_dir)
    os.makedirs(build_dir, exist_ok=True)
    os.chdir(build_dir)
    subprocess.check_call("cmake .. -DBUILD_SHARED_LIBS=OFF", shell=True)
    # 编译好的静态库位于 GmSSL-3.1.0/build/bin/libgmssl.a
    subprocess.check_call("make && make test", shell=True)

    # 切换回之前的目录
    os.chdir(cwd)


class CompileGmSSLLibrary(build_ext):
    """编译 GmSSL 静态库"""

    def run(self):
        compile_gmssl()
        super().run()


extension = Extension(
    "gmsslext",
    ["gmssl_pyx/gmsslmodule.c"],
    include_dirs=["./GmSSL-3.1.0/include"],
    library_dirs=["./GmSSL-3.1.0/build/bin"],
    libraries=["gmssl"],
)

setup(
    name="gmssl_pyx",
    description="python wrapper of GmSSL",
    version="1.0",
    ext_modules=[extension],
    cmdclass={"build_ext": CompileGmSSLLibrary},
)
