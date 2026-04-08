cmake_minimum_required(VERSION 4.1)
project(ObfuScan LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
        capstone
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        GIT_TAG 5.0.6
)

# 只做静态库，避免 DLL 依赖问题
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(capstone)

# 如果使用的是 MinGW 编译器，开启静态链接，把运行库打包进 exe
if(MINGW)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

add_executable(ObfuScan
        main.cpp
        miniz.c
        disasm_arm64.cpp
        disasm_arm64.h
)

target_include_directories(ObfuScan PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(ObfuScan PRIVATE capstone)

if (MSVC)
    target_compile_options(ObfuScan PRIVATE /W3 /EHsc /utf-8)
else()
    target_compile_options(ObfuScan PRIVATE -Wall -Wextra -O2)
endif()