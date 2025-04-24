add_library(CRSFParser STATIC)
add_library(CRSFAnalyser::CRSFParser ALIAS CRSFParser)

target_compile_features(CRSFParser PRIVATE cxx_std_17)
target_sources(CRSFParser PRIVATE CRSFParser.cpp)
target_include_directories(CRSFParser PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>")

## Installing
include(CMakePackageConfigHelpers)

install(
  TARGETS CRSFParser 
  EXPORT CRSFParserTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  INCLUDES DESTINATION include
)

install(
  EXPORT CRSFParserTargets
  FILE CRSFParserTargets.cmake
  NAMESPACE CRSFAnalyser::
  DESTINATION lib/cmake/CRSFParser
)
install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../include/CRSFParser 
  DESTINATION include
)
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/CRSFParserConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CRSFParser
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    CRSFParserConfigVersion.cmake
    VERSION ${PACKAGE_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(
  FILES 
    "${CMAKE_CURRENT_BINARY_DIR}/CRSFParserConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/CRSFParserConfigVersion.cmake"
  DESTINATION lib/cmake/CRSFParser
)
