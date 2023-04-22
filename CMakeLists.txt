cmake_minimum_required(VERSION 3.10)

project(my_project)

# 查找所有源文件
file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/**/*.c" )

#查找所有头文件
include_directories(${CMAKE_SOURCE_DIR}/)

# 添加可执行文件
add_executable(my_app ${SOURCES})