cmake_minimum_required(VERSION 3.15)

project(SigV4 LANGUAGES C)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/sigv4FilePaths.cmake)

# ------------------------------------------------------------------------------
# Library targets
# ------------------------------------------------------------------------------

add_library(sigv4_for_aws INTERFACE)

target_sources(sigv4_for_aws INTERFACE ${SIGV4_SOURCES})

target_include_directories(sigv4_for_aws INTERFACE ${SIGV4_INCLUDE_PUBLIC_DIRS})

message(STATUS "sigv4_for_aws library requires SIGV4_DO_NOT_USE_CUSTOM_CONFIG definition or a sigv4_config.h file.")
