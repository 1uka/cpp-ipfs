add_subdirectory(pb)
file(GLOB sources "*.cpp" "*.hpp")

add_library(libcrypto ${sources})
target_link_libraries(libcrypto common libmulti libcrypto_pb)
