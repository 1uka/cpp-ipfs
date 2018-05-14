#include <core/common.hpp>

namespace multi {
namespace base {


// TODO: create custom exceptions

enum Type : char
{
	Identity          = 0x00,
	Base1             = '1',
	Base2             = '0',
	Base8             = '7',
	Base10            = '9',
	Base16            = 'f',
	Base16Upper       = 'F',
	Base32            = 'b',
	Base32Upper       = 'B',
	Base32pad         = 'c',
	Base32padUpper    = 'C',
	Base32hex         = 'v',
	Base32hexUpper    = 'V',
	Base32hexPad      = 't',
	Base32hexPadUpper = 'T',
	Base58Flickr      = 'Z',
	Base58BTC         = 'z',
	Base64            = 'm',
	Base64url         = 'u',
	Base64pad         = 'M',
	Base64urlPad      = 'U'
};

static const int8_t mapBase58[256] = {
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

template<Type T>
struct Endec final
{
  static std::string encode(const bytes&);
  static bytes       decode(std::string);
};


constexpr char b16alphabet[] = "0123456789abcdef";
template<> std::string Endec<Type::Base16>::encode(const bytes&);
template<> bytes       Endec<Type::Base16>::decode(std::string);

constexpr char b32alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
template<> std::string Endec<Type::Base32>::encode(const bytes&);
template<> bytes       Endec<Type::Base32>::decode(std::string);

constexpr char b58alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
template<> std::string Endec<Type::Base58BTC>::encode(const bytes&);
template<> bytes       Endec<Type::Base58BTC>::decode(std::string);

constexpr char b64alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
template<> std::string Endec<Type::Base64>::encode(const bytes&);
template<> bytes       Endec<Type::Base64>::decode(std::string);



inline std::string encode(Type t, const bytes& input) 
{
  switch(t)
  {
    case Type::Base16:
      return (char) Type::Base16 + Endec<Type::Base16>().encode(input);
    case Type::Base32:
      return (char) Type::Base32 + Endec<Type::Base32>().encode(input);
    case Type::Base58BTC:
      return (char) Type::Base58BTC + Endec<Type::Base58BTC>().encode(input);
    case Type::Base64:
      return (char) Type::Base64 + Endec<Type::Base64>().encode(input);
    default:
      throw new std::invalid_argument("unknown encoding");
  }
}


inline bytes decode(std::string input)
{
  switch(input[0])
  {
    case (char) Type::Base16:
      return Endec<Type::Base16>().decode(input.substr(1, input.length() - 1));
    case (char) Type::Base32:
      return Endec<Type::Base32>().decode(input.substr(1, input.length() - 1));
    case (char) Type::Base58BTC:
      return Endec<Type::Base58BTC>().decode(input.substr(1, input.length() - 1));
    case (char) Type::Base64:
      return Endec<Type::Base64>().decode(input.substr(1, input.length() - 1));
    default:
      throw new std::invalid_argument("invalid input string/bad encoding");
  }
}

}
}

