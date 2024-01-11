cmake_minimum_required(VERSION 3.16)
include(cmake/ImHexExternalPlugin.cmake)
project(pcaps)
# Pin ImHex to a specific target tag.
# This can be a git tag, branch, or commit hash.
# Setting the IMHEX_OVERRIDE_TARGET_TAG variable when configuring the project will override this.
imhex_target_tag(v1.32.2)


if (CMAKE_CXX_BYTE_ORDER) 
    set(IS_BIG_ENDIAN, TRUE)
endif()
# Create a new ImHex plugin.
add_imhex_plugin(
    NAME
        pcaps

    SOURCES
        source/plugin_pcap.cpp

    INCLUDES
        include

    LIBRARIES
        pcap
)

if (APPLE)
    set_target_properties(pcaps PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/imhex.app/Contents/MacOS/plugins")
endif()
#add_dependencies(imhex_all pcaps)
