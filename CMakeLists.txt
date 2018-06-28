cmake_minimum_required(VERSION 3.11)

project(cpp-ipfs)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Ofast -g")

if(IOS_PLATFORM)
  set(CMAKE_CXX_FLAGS "-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -arch arm64 -I/usr/local/include -I/usr/local/Cellar/boost/1.67.0_1/include -I/usr/local/Cellar/cryptopp/7.0.0/include -L/usr/local/lib -Wno-aligned-allocation-unavailable")
endif()

include_directories("${CMAKE_SOURCE_DIR}")

add_subdirectory(common)
add_subdirectory(libmulti)
add_subdirectory(libcrypto)
add_subdirectory(libp2p)

add_executable(cpp_ipfs main.cpp)
target_link_libraries(cpp_ipfs libp2p)
