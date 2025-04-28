cmake_minimum_required(VERSION 3.25)
project(CRSFParser VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

option (WITH_LOGS "Use logging." ON)
if (WITH_LOGS)
	add_compile_definitions(LOG_ON)
endif ()

add_subdirectory(src)

find_package(Logger REQUIRED)

target_link_libraries(CRSFParser PUBLIC DebugTools::Logger)

