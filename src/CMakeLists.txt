# 设置可执行文件和 Windows DLL 的输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 设置静态库 (.lib/.a) 和 Windows 导入库 (.lib) 的输出目录
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 设置非 Windows 平台（如 Linux/macOS）下的共享库 (.so/.dylib) 输出目录
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_subdirectory(helpers)

add_subdirectory(samplewrapexistingcredentialprovider)