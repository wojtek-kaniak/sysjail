cmake_minimum_required(VERSION 3.10)

project(sysjail)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_EXPORT_COMPILE_COMMANDS True)

add_compile_options(-Wall)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_compile_options(-O0 -g3 -fsanitize=undefined)
	add_link_options(-g3 -fsanitize=undefined)
endif()

file(GLOB_RECURSE SOURCES src/*.cpp)
file(GLOB_RECURSE HEADERS src/*.hpp)
add_executable(sysjail ${SOURCES} ${HEADERS})

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	target_compile_definitions(sysjail PRIVATE DEBUG=1)
endif()

# Boost:
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_LIBRARIES ON)
find_package(Boost 1.79.0 COMPONENTS optional program_options)

target_include_directories(sysjail PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(sysjail ${Boost_LIBRARIES})
