cmake_minimum_required(VERSION 3.25)
project(CRSFParser VERSION 1.0)

add_subdirectory(src)

find_package(Logger REQUIRED)

target_link_libraries(CRSFParser PUBLIC DebugTools::Logger)

