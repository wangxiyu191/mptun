cmake_minimum_required(VERSION 3.7)
project(mptun)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        mptun.cpp)

add_executable(mptun ${SOURCE_FILES})