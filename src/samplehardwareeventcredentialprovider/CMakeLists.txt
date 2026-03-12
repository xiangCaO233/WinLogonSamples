add_library(SampleHardwareEventCredentialProvider SHARED
	guid.cpp
	CSampleProvider.cpp
	CSampleCredential.cpp
	CommandWindow.cpp
	MessageCredential.cpp
	resources.rc
	SampleHardwareEventCredentialProvider.def
)

target_include_directories(SampleHardwareEventCredentialProvider
	PRIVATE ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(SampleHardwareEventCredentialProvider
	PRIVATE
		Helpers
		Shlwapi.lib
		Netapi32.lib
		credui.lib
		ole32.lib # COM 需要
		user32.lib # 以后可能用到
		Secur32.lib
)