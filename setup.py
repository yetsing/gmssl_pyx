#!/usr/bin/env python3
import os
import sys
import urllib.request
import shutil
import subprocess
import tarfile

from setuptools.command.build_ext import build_ext
from setuptools import setup, Extension


is_windows = sys.platform.startswith("win32")


def download_source_code():
    if os.path.exists("GmSSL-3.1.0"):
        shutil.rmtree("GmSSL-3.1.0")
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

    if not is_windows:
        # 2. 修改 CMakeLists.txt ，直接编译会报错
        # /usr/bin/ld: ./GmSSL-3.1.0/build/bin/libgmssl.a(sm2_key.c.o): relocation R_X86_64_PC32 against symbol `stderr@@GLIBC_2.2.5' can not be used when making a shared object; recompile with -fPIC
        cmake_filename = "GmSSL-3.1.0/CMakeLists.txt"
        append_text = "add_compile_options(-fPIC)"
        with open(cmake_filename, "r") as f:
            text = f.read()
            # rand_unix.需要使用 getentropy
            # getentropy 在老版本的Linux发行版和glibc中不存在
        text = text.replace('rand_unix.c', 'rand.c')
        # macos Symbol not found: _kSecRandomDefault
        text = text.replace('-framework Security', '-framework Security -framework Foundation')
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
    os.chdir("GmSSL-3.1.0")
    if os.path.exists('build'):
        # 删除之前的构建，重新生成
        shutil.rmtree('build')
    subprocess.check_call("cmake -B build -DBUILD_SHARED_LIBS=OFF", shell=True)
    subprocess.check_call("cmake --build build", shell=True)

    # 切换回之前的目录
    os.chdir(cwd)


class CompileGmSSLLibrary(build_ext):
    """编译 GmSSL 静态库"""

    def run(self):
        compile_gmssl()
        super().run()


extension = Extension(
    "gmssl_pyx.gmsslext",
    ["gmssl_pyx/gmsslmodule.c"],
    include_dirs=["./GmSSL-3.1.0/include"],
    library_dirs=["./GmSSL-3.1.0/build/bin"],
    libraries=["gmssl"],
)

setup(
    name="gmssl_pyx",
    description="python wrapper of GmSSL",
    version="0.0.1",
    url="https://github.com/yetsing/gmssl_pyx",
    author="yeqing",
    license="Apache Software License",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: C",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    python_requires=">=3.7",
    keywords="gmssl",
    packages=[
        'gmssl_pyx',
    ],
    ext_modules=[extension],
    cmdclass={"build_ext": CompileGmSSLLibrary},
)
