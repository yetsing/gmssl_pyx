#!/usr/bin/env python3
import os
import pathlib
import sys
import urllib.request
import shutil
import subprocess
import tarfile

from setuptools.command.build_ext import build_ext
from setuptools import setup, Extension


# 需要给所有文件读写操作都指定编码，避免 windows gbk 编码错误
utf8 = "utf-8"
script_directory = pathlib.Path(__file__).resolve().parent
is_windows = sys.platform.startswith("win32")
long_description = script_directory.joinpath("README.md").read_text(encoding=utf8)


def get_version() -> str:
    version_filepath = script_directory.joinpath("gmssl_pyx", "_version.py")
    version_dict = {}
    exec(version_filepath.read_text(encoding=utf8), {}, version_dict)
    return version_dict["__version__"]


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
    if os.path.exists("./GmSSL-3.1.0/build/bin/libgmssl.a"):
        return
    cwd = os.getcwd()
    # 下载 GmSSL 库编译成静态库
    # 1.下载源码并解压
    download_source_code()

    os.chdir("GmSSL-3.1.0")
    if sys.platform.startswith("linux"):
        # 2. 修改 CMakeLists.txt ，直接编译会报错
        # /usr/bin/ld: ./GmSSL-3.1.0/build/bin/libgmssl.a(sm2_key.c.o): relocation R_X86_64_PC32 against symbol `stderr@@GLIBC_2.2.5' can not be used when making a shared object; recompile with -fPIC
        cmake_filename = "CMakeLists.txt"
        with open(cmake_filename, "r", encoding=utf8) as f:
            text = f.read()
        # rand_unix.需要使用 getentropy
        # getentropy 在老版本的Linux发行版和 glibc 中不存在
        text = text.replace("rand_unix.c", "rand.c")
        # 根据错误说明增加编译选项 -fPIC ，加在 "project(GmSSL)" 后面
        append_text = "add_compile_options(-fPIC)"
        text = text.replace(
            "project(GmSSL)",
            "project(GmSSL)\n\n{}\n\n".format(append_text),
        )
        with open(cmake_filename, "w", encoding=utf8) as f:
            f.write(text)

    elif sys.platform.startswith("win"):
        # 修改 sm2.h 内容，直接用 windows 编译会报语法错误
        # 具体原因不清楚，不想深究了
        filename = "include/gmssl/sm2.h"
        with open(filename, "r", encoding=utf8) as f:
            text = f.read()
        text = text.replace("#include <gmssl/api.h>", "")
        text = text.replace("_gmssl_export", "__declspec(dllexport)")
        with open(filename, "w", encoding=utf8) as f:
            f.write(text)

    # 3.编译静态库
    if os.path.exists("build"):
        # 删除之前的构建，重新生成
        shutil.rmtree("build")
    # 这两条编译命令来自 GmSSLL 的 github action 配置，文件链接如下
    # https://github.com/guanzhi/GmSSL/blob/v3.1.0/.github/workflows/cmake.yml
    subprocess.check_call("cmake -B build -DBUILD_SHARED_LIBS=OFF", shell=True)
    subprocess.check_call("cmake --build build", shell=True)

    # 切换回之前的目录
    os.chdir(cwd)


class CompileGmSSLLibrary(build_ext):
    """编译 GmSSL 静态库"""

    def run(self):
        compile_gmssl()
        super().run()


def create_extension():
    extra_link_args = []
    library_dirs = ["./GmSSL-3.1.0/build/bin"]
    libraries = ["gmssl"]
    if sys.platform.startswith("darwin"):
        # macos Symbol not found: _kSecRandomDefault
        # 对应 GmSSL-3.1.0/src/rand_apple.c
        extra_link_args = ["-framework", "Security"]
    elif sys.platform.startswith("win"):
        # windows security random, 对应 GmSSL-3.1.0/src/rand_win.c
        library_dirs = ["./GmSSL-3.1.0/build/bin/Debug"]
        libraries.append("Advapi32")
    extension = Extension(
        "gmssl_pyx.gmsslext",
        ["gmssl_pyx/gmsslmodule.c"],
        include_dirs=["./GmSSL-3.1.0/include"],
        library_dirs=library_dirs,
        libraries=libraries,
        extra_link_args=extra_link_args,
    )
    return extension


setup(
    name="gmssl_pyx",
    description="python wrapper of GmSSL",
    long_description=long_description,
    long_description_content_type="text/markdown",
    version=get_version(),
    url="https://github.com/yetsing/gmssl_pyx",
    author="yeqing",
    license="Apache Software License",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Operating System :: Unix",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Security :: Cryptography",
        "Programming Language :: C",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    python_requires=">=3.7",
    keywords="gmssl",
    packages=[
        "gmssl_pyx",
    ],
    ext_modules=[create_extension()],
    cmdclass={"build_ext": CompileGmSSLLibrary},
)
