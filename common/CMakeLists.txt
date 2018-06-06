file(GLOB sources "*.cpp" "*.hpp")

add_library(common ${sources})
target_link_libraries(common -lboost_system -lboost_fiber-mt)
