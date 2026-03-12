add_library(SampleCredentialProvider SHARED
	guid.cpp
	CSampleProvider.cpp
	CSampleCredential.cpp
	resources.rc
	SampleCredentialProvider.def
)

target_include_directories(SampleCredentialProvider
	PRIVATE ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(SampleCredentialProvider
	PRIVATE
		Helpers
		Shlwapi.lib
		Netapi32.lib
		credui.lib
		ole32.lib # COM 需要
		user32.lib # 以后可能用到
		Secur32.lib
)