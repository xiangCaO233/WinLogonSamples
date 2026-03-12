add_library(SampleWrapExistingCredentialProvider SHARED
	guid.cpp
	CSampleProvider.cpp
	CSampleCredential.cpp
	CWrappedCredentialEvents.cpp
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