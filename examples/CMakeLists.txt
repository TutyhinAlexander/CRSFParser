cmake_minimum_required(VERSION 3.25)
project(CRSFParserTest VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(CRSFParserTest CRSFParserTest.cpp)

find_package(CRSFParser REQUIRED)
find_package(Logger REQUIRED)

target_link_libraries(CRSFParserTest PUBLIC DebugTools::Logger CRSFAnalyser::CRSFParser)
