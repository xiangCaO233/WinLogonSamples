add_library(SampleWrapExistingCredentialProvider SHARED
	guid.cpp
	provider/CSampleProvider.cpp
	provider/CSampleProviderAdvise.cpp
	provider/CSampleProviderCredential.cpp
	provider/CSampleProviderFieldDescriptor.cpp
	provider/CSampleProviderSetSerialization.cpp
	provider/CSampleProviderUsageScenario.cpp
	"filter/CSampleProviderFilter.cpp"
	credential/CSampleCredential.cpp
	credential/events/CWrappedCredentialEvents.cpp
	resources.rc
	SampleWrapExistingCredentialProvider.def
)

target_include_directories(SampleWrapExistingCredentialProvider
	PRIVATE ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(SampleWrapExistingCredentialProvider
	PRIVATE
		Helpers
		Shlwapi.lib
		Netapi32.lib
		credui.lib
		ole32.lib # COM 需要
		user32.lib # 以后可能用到
		Secur32.lib
)

set(REGISTERS
	"${CMAKE_CURRENT_SOURCE_DIR}/Register.reg"
	"${CMAKE_CURRENT_SOURCE_DIR}/Unregister.reg"
)

# 添加自定义命令
add_custom_command(
	TARGET SampleWrapExistingCredentialProvider
	POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E copy ${REGISTERS}
		"$<TARGET_FILE_DIR:SampleWrapExistingCredentialProvider>"
	COMMENT "Copying registers to output directory..."
)