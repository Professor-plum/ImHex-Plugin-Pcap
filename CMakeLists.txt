cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 20)

# Include ImHex cmake module #
set(IMHEX_BASE_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/ImHex)
set(CMAKE_MODULE_PATH "${IMHEX_BASE_FOLDER}/cmake/modules")
include("${IMHEX_BASE_FOLDER}/cmake/build_helpers.cmake")

# Create OS and Architecture defines #
detectOS()
detectArch()

# Change this to the name of your plugin #
project(example_cpp)

# Add your source files here #
add_library(${PROJECT_NAME} SHARED
        source/plugin_example.cpp
)

# Add additional include directories here #
target_include_directories(${PROJECT_NAME} PRIVATE include)
# Add additional libraries here #
add_subdirectory(${IMHEX_BASE_FOLDER}/plugins/libimhex)
target_link_libraries(${PROJECT_NAME} PRIVATE libimhex)


# ---- No need to change anything from here downwards unless you know what you're doing ---- #

set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".hexplug")

if (WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--allow-multiple-definition -fvisibility=hidden")
endif()

add_compile_definitions(IMHEX_PLUGIN_NAME=${PROJECT_NAME})

