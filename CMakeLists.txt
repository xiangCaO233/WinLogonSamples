cmake_minimum_required(VERSION 4.0.0)

# 1. 先定义变量
option(BUILD_FOR_WIN7 "build demo for windows 7" ON)

# 2. 在 project() 之前设置系统版本
if(BUILD_FOR_WIN7)
	set(CMAKE_SYSTEM_VERSION 6.1)
endif()

project(CredentialProviderDemo LANGUAGES C CXX)

# 3. 打印信息确保逻辑执行
if(BUILD_FOR_WIN7)
	message(STATUS ">>>>>> Target System: Windows 7 (6.1)")
	add_definitions(-D_WIN32_WINNT=0x0601)
	add_definitions(-DWINVER=0x0601)
	add_definitions(-DNTDDI_VERSION=0x06010000)
	add_definitions(-DBUILD_FOR_WIN7)
endif()

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_subdirectory(src)