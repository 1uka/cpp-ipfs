file(GLOB sources "*.cpp" "*.hpp")

add_library(libmulti ${sources})
target_link_libraries(libmulti common -lcryptopp)