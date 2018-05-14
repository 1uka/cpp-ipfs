#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

using bigint = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<>>;
using byte  = uint8_t;
using bytes = std::vector<byte>;