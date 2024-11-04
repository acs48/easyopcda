cmake_minimum_required(VERSION 3.16)
project(easyopcda)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(spdlog-1.14.1)

add_library(easyopcda_lib STATIC
        src/opcclient.cpp
        src/opccomn_i.c
        src/opcda_i.c
        src/OpcEnum_i.c
        src/opcgroup.cpp
        src/opcinit.cpp
)
target_include_directories(easyopcda_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(easyopcda_lib PRIVATE spdlog_lib)

add_executable(easyopcda_example src/example.cpp)
target_include_directories(easyopcda_example PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(easyopcda_example PRIVATE easyopcda_lib)
target_link_libraries(easyopcda_example PRIVATE spdlog_lib)

