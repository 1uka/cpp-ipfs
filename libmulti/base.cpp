#include "base.hpp"

namespace multi {
namespace base {


template<>
std::string Endec<Type::Base16>::encode(const bytes& input)
{
  size_t length = input.size();
  std::string output;
  output.reserve(2 * length);

  for(size_t i = 0; i < length; i++)
  {
    output.push_back(b16alphabet[input[i] >> 4]);
    output.push_back(b16alphabet[input[i] & 15]);
  }

  return output;
}

template<>
bytes Endec<Type::Base16>::decode(std::string input)
{
  const char* alphabet = b16alphabet;
  size_t length = input.size();

  if(length & 1) throw std::invalid_argument("odd length string");

  bytes output(length / 2);
  for(size_t i = 0; i < length; i += 2)
  {
    const char* p = std::lower_bound(alphabet, alphabet + 16, input[i]);
    if(*p != input[i]) throw std::invalid_argument("contains non-hex digits");

    const char* q = std::lower_bound(alphabet, alphabet + 16, input[i + 1]);
    if(*q != input[i + 1]) throw std::invalid_argument("contains non-hex digits");

    output.push_back(((p - alphabet) << 4) | (q - alphabet));
  }

  return output;
}


template<>
std::string Endec<Type::Base32>::encode(const bytes& input)
{
  size_t length = input.size();

  uint32_t bits = 0;
  uint32_t value = 0;
  std::string output;

  for(size_t i = 0; i < length; i++)
  {
    value = (value << 8) | input[i];
    bits += 8;

    while(bits >= 5)
    {
      output += b32alphabet[(value >> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if(bits > 0) { output += b32alphabet[(value << (5 - bits)) & 31]; }

  return output;
}

template<>
bytes Endec<Type::Base32>::decode(std::string input)
{
  std::replace(input.begin(), input.end(), '=', 'g');

  size_t lenght = input.length();
  uint32_t bits = 0;
  uint32_t value = 0;
  int index = 0;

  bytes output((lenght * 5 / 8) | 0);
  for(size_t i = 0; i < lenght; i++)
  {
    value = (value << 5) | std::string(b32alphabet).find(tolower(input[i]));
    bits += 5;

    if(bits >= 8)
    {
      output[index++] = (value >> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }

  return output;
}


template<>
std::string Endec<Type::Base58BTC>::encode(const bytes& input)
{
  const unsigned char* pbegin = input.data(); 
  const unsigned char* pend = input.data() + input.size();

  // Skip & count leading zeroes.
  int zeroes = 0;
  int length = 0;
  while (pbegin != pend && *pbegin == 0) 
  {
    pbegin++;
    zeroes++;
  }
  // Allocate enough space in big-endian base58 representation.
  int size = (pend - pbegin) * 138 / 100 + 1; // log(256) / log(58), rounded up.
  std::vector<unsigned char> b58(size);
  // Process the bytes.
  while (pbegin != pend) 
  {
    int carry = *pbegin;
    int i = 0;
    // Apply "b58 = b58 * 256 + ch".
    for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) 
    {
      carry += 256 * (*it);
      *it = carry % 58;
      carry /= 58;
    }

    assert(carry == 0);
    length = i;
    pbegin++;
  }
  // Skip leading zeroes in base58 result.
  std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
  while (it != b58.end() && *it == 0) { it++; }
  // Translate the result into a string.
  std::string str;
  str.reserve(zeroes + (b58.end() - it));
  str.assign(zeroes, '1');
  while (it != b58.end()) 
    str += b58alphabet[*(it++)]; 

  return str;
}

template<>
bytes Endec<Type::Base58BTC>::decode(std::string input)
{
  const char* psz = input.c_str();
  bytes vch;
  // Skip leading spaces.
  while (*psz && isspace(*psz)) { psz++; }
  // Skip and count leading '1's.
  int zeroes = 0;
  int length = 0;
  while (*psz == '1') {
    zeroes++;
    psz++;
  }
  // Allocate enough space in big-endian base256 representation.
  int size = strlen(psz) * 733 /1000 + 1; // log(58) / log(256), rounded up.
  std::vector<unsigned char> b256(size);
  // Process the characters.
  static_assert(sizeof(mapBase58)/sizeof(mapBase58[0]) == 256, "mapBase58.size() should be 256"); // guarantee not out of range
  while (*psz && !isspace(*psz)) 
  {
    // Decode base58 character
    int carry = mapBase58[(uint8_t)*psz];
    if (carry == -1)  { return bytes(0); }
    int i = 0;
    for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) 
    {
      carry += 58 * (*it);
      *it = carry % 256;
      carry /= 256;
    }
    assert(carry == 0);
    length = i;
    psz++;
  }
  // Skip trailing spaces.
  while (isspace(*psz)) { psz++; }
  if (*psz != 0) { return bytes(0); }
  // Skip leading zeroes in b256.
  std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
  while (it != b256.end() && *it == 0) { it++; }
  // Copy result into output vector.
  vch.reserve(zeroes + (b256.end() - it));
  vch.assign(zeroes, 0x00);
  while (it != b256.end()) { vch.push_back(*(it++)); }
  return vch;
}



template<>
std::string Endec<Type::Base64>::encode(const bytes& input)
{
  std::string output;
  size_t i;
  unsigned char a3[3], a4[4];

  for(i = 0; i < input.size(); i++)
  {
    a3[i % 3] = input[i];
    if((i + 1) % 3 == 0)
    {
      a4[0] = (a3[0] & 0xfc) >> 2;
      a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
      a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
      a4[3] = a3[2] & 0x3f;

      for(size_t j = 0; j < 4; j++) { output += b64alphabet[a4[j]]; }
    }
  }

  i = i % 3;
  if(i)
  {
    for(size_t j = i; j < 3; j++) { a3[j] = '\0'; }

    a4[0] = (a3[0] & 0xfc) >> 2;
    a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
    a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);

    for(size_t j = 0; j < i + 1; j++) { output += b64alphabet[a4[j]]; }

    while(i++ < 3) { output += '='; }
  }

  return output;
}

template<>
bytes Endec<Type::Base64>::decode(std::string input)
{
  constexpr auto is_base64 = [](const unsigned char& c) -> bool { return (isalnum(c) || (c == '+') || (c == '/')); };
  std::string alphabet(b64alphabet);
  bytes output;
  size_t length = input.length();
  size_t i, j;
  unsigned char a3[3], a4[4];

  for(i = 0; i < length; i++)
  {
    if(!is_base64(input[i]) || (input[i] == '=')) { break; }
    a4[i % 4] = input[i];
    if((i + 1) % 4 == 0)
    {
      for(j = 0; j < 4; j++) { a4[j] = alphabet.find(a4[j]); }

      a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
      a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
      a3[2] = ((a4[2] & 0x3) << 6) + a4[3];

      for(j = 0; j < 3; j++) { output.push_back(a3[j]); }
    }
  }

  i = i % 4;
  if(i)
  {
    for(j = 0; j < i; j++) { a4[j] = alphabet.find(a4[j]); }
    a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
    a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);

    for (j = 0; j < i - 1; j++) { output.push_back(a3[j]); }
  }

  return output;
}


}
}