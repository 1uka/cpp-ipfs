file(GLOB sources "*.cpp" "*.hpp")

add_library(libp2p ${sources})
target_link_libraries(libp2p libcrypto)