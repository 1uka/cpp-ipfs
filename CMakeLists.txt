cmake_minimum_required(VERSION 3.11)

project(cpp-ipfs)
set(CMAKE_CXX_STANDARD 17)

include_directories("${CMAKE_SOURCE_DIR}")

add_subdirectory(common)
add_subdirectory(libmulti)
add_subdirectory(libcrypto)
add_subdirectory(libp2p)

add_executable(cpp_ipfs main.cpp)
target_link_libraries(cpp_ipfs libp2p)
