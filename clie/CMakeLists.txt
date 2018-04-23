# Version
cmake_minimum_required(VERSION 1.0)

# project info
project(cli)

# set source dircetory
aux_source_directory(. DIR_SRSC)

# target
add_executable(cli ${DIR_SRSC})
