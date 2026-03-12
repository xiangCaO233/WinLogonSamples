add_library(SampleAllControlsCredentialProvider SHARED
	guid.cpp
	CSampleProvider.cpp
	CSampleCredential.cpp
	resources.rc
	sampleallcontrolscredentialprovider.def
)

target_include_directories(SampleAllControlsCredentialProvider
	PRIVATE ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(SampleAllControlsCredentialProvider
	PRIVATE
		Helpers
		Shlwapi.lib
		Netapi32.lib
		credui.lib
		ole32.lib # COM 需要
		user32.lib # 以后可能用到
		Secur32.lib
)