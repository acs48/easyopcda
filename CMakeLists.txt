cmake_minimum_required(VERSION 3.16)
project(easyopcda)

set(CMAKE_CXX_STANDARD 17)

add_library(easyopcda_lib STATIC
        src/opcClient.cpp
        src/opccomn_i.c
        src/opcda_i.c
        src/OpcEnum_i.c
        src/opcGroup.cpp
        src/opcInit.cpp
)
target_include_directories(easyopcda_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
