cmake_minimum_required(VERSION 3.16)
project(gmssl_pyx C)

set(CMAKE_C_STANDARD 99)
include_directories(
        ~/.pyenv/versions/3.7.16/include/python3.7m
        GmSSL-3.1.0/include
)
link_directories(
        ~/.pyenv/versions/3.7.16/lib
        GmSSL-3.1.0//build/bin
)
link_libraries(python3.7m gmssl)
add_library(gmssl_ext SHARED gmssl_pyx/gmsslmodule.c)
