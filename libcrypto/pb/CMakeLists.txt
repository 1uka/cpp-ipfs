file(GLOB sources "*.cc" "*.h")

add_library(libcrypto_pb crypto.pb.cc crypto.pb.h)
target_link_libraries(libcrypto_pb -lprotobuf)