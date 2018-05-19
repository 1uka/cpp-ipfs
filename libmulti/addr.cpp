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
	if(b.size() != 4) { return ""; }
	std::array<unsigned char, 4UL> ip;
	for(size_t i = 0; i < 4UL; i++)
	{
		ip[i] = b[i];
	}
	return ip4addr(ip).to_string();
}

std::string ip6b2s(const bytes& b)
{
	if(b.size() != 16) { return ""; }
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
	if(b.size() > 2) { return ""; }
	uint16_t port = ((uint16_t) b[0] << 8) + (uint16_t) b[1];
	return std::to_string(port);
}


bytes ipfss2b(const std::string& s)
{
	try
	{
		multi::hash::Decoded mh = multi::hash::from_string(s);
		bytes b;
		put_uvarint(b, mh.len());
		b.insert(b.end(), mh.hash().begin(), mh.hash().end());
		return b;
	} catch(const Exception& e)
	{
		throw e;
	}
}

std::string ipfsb2s(const bytes& b)
{
	int len;
	int size;
	size = uvarint(b, &len);
	bytes hash(b.begin() + len, b.end());
	// if(hash.size() != size) { throw Exception("inconsistent lengths"); }

	return multi::base::encode(hash);
}


protocol proto_with_name(const std::string& s)
{
	for(auto&& p : protocols)
	{
		if(p.m_name == s) { return p; }
	}
	return protocol();
}

protocol proto_with_code(const int& c)
{
	for(auto&& p : protocols)
	{
		if(p.m_code == c) { return p; }
	}
	return protocol();
}

bytes string2bytes(std::string s)
{
	auto isBackspace = [](char c) { return c == '/'; };
	std::vector<std::string> tokens;
	bytes buf;
	boost::trim_right_if(s, isBackspace);
	boost::split(tokens, s, isBackspace);
	if(tokens[0] != "") 
	{ 
		throw Exception("Invalid multiaddress, must begin with /"); 
	}

	tokens.erase(tokens.begin());

	while(tokens.size() > 0)
	{
		protocol p = proto_with_name(tokens[0]);
		if(p.m_code == 0) 
		{ 
			throw Exception("address contains invalid protocol"); 
		}

		put_varint(buf, p.m_code);
		tokens.erase(tokens.begin());

		if(p.m_size == 0) continue;
		if(tokens.size() < 1)
		{
			throw Exception("protocol requires address, none given");
		}

		if(p.m_path)
		{
			tokens[0] = "/" + boost::join(tokens, "/");
		}
		if(!p.m_has_transc)
		{
			throw Exception("no transcoder for protocol " + p.m_name);
		}

		try
		{
			bytes a = p.m_transcoder.string2bytes(tokens[0]);
			buf.insert(buf.end(), a.begin(), a.end());
			tokens.erase(tokens.begin());
		} catch(const Exception& e)
		{
			throw Exception("failed to parse " + p.m_name);
		}
	}
	
	return buf;
}

std::string bytes2string(bytes b)
{
	std::string s = "";
	while(b.size() > 0)
	{
		int len, code;
		code = varint(b, &len);
		if(len <= 0) return "";

		b.erase(b.begin(), b.begin() + len);
		protocol p = proto_with_code(code);
		if(p.m_code == 0) 
		{ 
			throw Exception("address contains invalid protocol"); 
		}
		s += "/" + p.m_name;
		if(p.m_size == 0) continue;

		int size = size_for_addr(p, b);
		
		if(b.size() < size || size < 0)
		{
			throw Exception("invalid value for size");
		}

		if(!p.m_has_transc)
		{
			throw Exception("no transcoder for protocol " + p.m_name);
		}

		try
		{
			std::string a = p.m_transcoder.bytes2string(bytes(b.begin(), b.begin() + size));
			if(a.length() > 0)
			{
				s += "/" + a;
			}
			b.erase(b.begin(), b.begin() + size);
		} catch(const Exception& e)
		{
			throw Exception("failed to parse " + p.m_name);
		}
	}

	return s;
}

int size_for_addr(const protocol& p, const bytes& b)
{
	if(p.m_size > 0) {
		return p.m_size / 8;
	} else if(p.m_size == 0) {
		return 0;
	} else {
		int n;
		int x = varint(b, &n);
		if(n <= 0) return 0;
		return x + n;
	}
}


}
}
