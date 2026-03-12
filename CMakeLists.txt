cmake_minimum_required(VERSION 4.0.0)

project(CredentialProviderDemo LANGUAGES C CXX)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# 强制要求 x64 位输出（因为 Win10 64位系统不加载 32位 CP）
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	message(FATAL_ERROR "You must build this project for x64!")
endif()

add_subdirectory(src)

# 关键：Credential Provider 必须是 DLL
# add_library(${PROJECT_NAME} SHARED
# 	src/ExampleCredential.cpp
# 	src/ExampleProvider.cpp
# 	src/CredentialProviderExample.cpp
# 	src/module.def
# )
#
# target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/src)
#
# # 链接 Windows 必要的库
# target_link_libraries(${PROJECT_NAME}
# 	PUBLIC
# 		Shlwapi.lib
# 		Netapi32.lib
# 		credui.lib
# 		ole32.lib # COM 需要
# 		user32.lib # 以后可能用到
# )