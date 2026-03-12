add_library(Helpers STATIC
	helpers.cpp
	Dll.cpp
)

target_include_directories(Helpers PUBLIC ${CMAKE_CURRENT_LIST_DIR})