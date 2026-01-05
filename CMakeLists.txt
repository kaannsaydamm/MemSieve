cmake_minimum_required(VERSION 3.10)
project(MemSieveTracer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(tracer src/main.cpp src/tracer.cpp)
target_include_directories(tracer PUBLIC src)

# Ensure output goes to build directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
