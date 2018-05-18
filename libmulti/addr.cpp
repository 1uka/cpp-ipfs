#include "addr.hpp"

namespace multi {
namespace addr {


bytes ip4s2b(const std::string& s)
{
	ip4bytes ip4b = ip4addr::from_string(s).to_bytes();
	return bytes(ip4b.begin(), ip4b.end());
}

bytes ip6s2b(const std::string& s)
{
	ip6bytes ip6b = ip6addr::from_string(s).to_bytes();
	return bytes(ip6b.begin(), ip6b.end());
}

std::string ip4b2s(const bytes& b)
{
	if(b.size() != 4) { throw Exception("invalid ip4 address"); }
	std::array<unsigned char, 4UL> ip;
	for(size_t i = 0; i < 4UL; i++)
	{
		ip[i] = b[i];
	}
	return ip4addr(ip).to_string();
}

std::string ip6b2s(const bytes& b)
{
	if(b.size() != 16) { throw Exception("invalid ip6 address"); }
	std::array<unsigned char, 16UL> ip;
	for(size_t i = 0; i < 16UL; i++)
	{
		ip[i] = b[i];
	}
	return ip6addr(ip).to_string();
}


bytes ports2b(const std::string& s)
{
	int i = atoi(s.c_str());
	if(i > UINT16_MAX) { throw Exception("failed to parse port addr; greater than UINT16_MAX"); }
	bytes b(2);
	b[0] = (uint8_t) i >> 8;
	b[1] = (uint8_t) i & 0xff;
	return b;
}

std::string portb2s(const bytes& b)
{
	if(b.size() > 2) { throw Exception("buffer overflows port"); }
	uint16_t port = ((uint16_t) b[0] << 8) + (uint16_t) b[1];
	return std::to_string(port);
}


bytes ipfss2b(const std::string& s)
{
	multi::hash::Decoded mh = multi::hash::from_string(s);
	bytes b;
	put_uvarint(b, mh.len());
	b.insert(b.end(), mh.hash().begin(), mh.hash().end());
	return b;
}

std::string ipfsb2s(const bytes& b)
{
	int len;
	int size;
	try
	{
		size = uvarint(b, &len);
	} catch(const Exception& e)
	{
		throw Exception("could not get varint prefix from address");
	}
	bytes hash(b.begin() + len, b.end());
	if(hash.size() != size) { throw Exception("inconsistent lengths"); }

	return multi::base::encode(hash);
}


}
}
