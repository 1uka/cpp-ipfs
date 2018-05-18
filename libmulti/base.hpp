/**
 * @brief Multibase implementation in cpp
 * 
 * @file base.hpp
 * @author Luka Atanasovski
 * @date 2018-05-15
 */

#include <common/types.hpp>

namespace multi {
namespace base {



/**
 * @brief Base encodings
 * 
 */
enum type : char
{
	// Identity          = 0x00,
	// b1             = '1',
	// b2             = '0',
	// b8             = '7',
	// b10            = '9',
	b16            = 'f',
	// b16Upper       = 'F',
	b32            = 'b',
	// b32Upper       = 'B',
	// b32pad         = 'c',
	// b32padUpper    = 'C',
	// b32hex         = 'v',
	// b32hexUpper    = 'V',
	// b32hexPad      = 't',
	// b32hexPadUpper = 'T',
	// b58Flickr      = 'Z',
	b58BTC         = 'z',
	b64            = 'm'
	// b64url         = 'u',
	// b64pad         = 'M',
	// b64urlPad      = 'U'
};



constexpr int8_t mapBase58[256] = {
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
		-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
		22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
		-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
		47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};



constexpr char b16alphabet[] = "0123456789abcdef";
std::string b16_encode(const bytes&);
bytes 			b16_decode(const std::string&);

constexpr char b32alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
std::string b32_encode(const bytes&);
bytes       b32_decode(const std::string&);

constexpr char b58alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
std::string b58btc_encode(const bytes&);
bytes       b58btc_decode(const std::string&);

constexpr char b64alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string b64_encode(const bytes&);
bytes       b64_decode(const std::string&);



inline std::string encode(const bytes& input, type t = b58BTC)
{
	switch(t)
	{
		case type::b16:
			return (char) type::b16 + b16_encode(input);
		case type::b32:
			return (char) type::b32 + b32_encode(input);
		case type::b58BTC:
			return (char) type::b58BTC + b58btc_encode(input);
		case type::b64:
			return (char) type::b64 + b64_encode(input);
		default:
			throw Exception("unknown encoding");
	}
}


inline bytes decode(std::string input)
{
	switch(input[0])
	{
		case type::b16:
			return b16_decode(input.substr(1, input.length() - 1));
		case type::b32:
			return b32_decode(input.substr(1, input.length() - 1));
		case type::b58BTC:
			return b58btc_decode(input.substr(1, input.length() - 1));
		case type::b64:
			return b64_decode(input.substr(1, input.length() - 1));
		default:
			throw Exception("invalid input string/unknown encoding");
	}
}


}
}

