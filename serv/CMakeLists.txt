# Version
cmake_minimum_required(VERSION 1.0)

# project info
project(serv)

# set source dircetory
aux_source_directory(. DIR_SRSC)

# target
add_executable(serv ${DIR_SRSC})
