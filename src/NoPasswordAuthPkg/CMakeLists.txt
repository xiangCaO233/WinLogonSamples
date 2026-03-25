add_library(NoPasswordAuthPkg SHARED
	Main.cpp
	Utils.hpp
	PrepareProfile.hpp
	PrepareProfile.cpp
	PrepareToken.hpp
	PrepareToken.cpp
)

target_compile_definitions(NoPasswordAuthPkg
	PRIVATE
		SECURITY_WIN32
		UMDF_USING_NTSTATUS
)

target_include_directories(NoPasswordAuthPkg
	PRIVATE ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(NoPasswordAuthPkg
	PRIVATE
		Secur32
		Netapi32
)

set(SCRIPTS
	"${CMAKE_CURRENT_SOURCE_DIR}/Install_NoPasswordAuthPkg.ps1"
	"${CMAKE_CURRENT_SOURCE_DIR}/Uninstall_NoPasswordAuthPkg.ps1"
)

# 添加自定义命令
add_custom_command(
	TARGET NoPasswordAuthPkg
	POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy ${SCRIPTS}
		"$<TARGET_FILE_DIR:NoPasswordAuthPkg>"
	COMMENT "Copying installation scripts to output directory..."
)