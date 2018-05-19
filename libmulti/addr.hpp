/**
 * @brief Multiaddress
 * 
 * @file addr.hpp
 * @author Luka Atanasovski
 * @date 2018-05-19
 */


#ifndef MULTIADDR_H
#define MULTIADDR_H



#include <common/types.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>

#include "hash.hpp"


namespace multi {
namespace addr {

using ipaddr = boost::asio::ip::address;

using ip4addr = boost::asio::ip::address_v4;
using ip4bytes = ip4addr::bytes_type;

using ip6addr = boost::asio::ip::address_v6;
using ip6bytes = ip6addr::bytes_type;

typedef bytes (*strtobytes)(const std::string&);
typedef std::string (*bytestostr)(const bytes&);

class transcoder
{
public:
	transcoder() = default;
	~transcoder() = default;

	explicit transcoder(strtobytes _s2b, bytestostr _b2s) : f_s2b(_s2b), f_b2s(_b2s) {};

	inline bytes  string2bytes(const std::string& _s) const { return f_s2b(_s); }
	inline std::string bytes2string(const bytes& _b) const { return f_b2s(_b); }
private:
	strtobytes f_s2b;
	bytestostr f_b2s;
};

bytes ip4s2b(const std::string&);
bytes ip6s2b(const std::string&);
std::string ip4b2s(const bytes&);
std::string ip6b2s(const bytes&);
static const transcoder ip4_transcoder(&ip4s2b, &ip4b2s);
static const transcoder ip6_transcoder(&ip6s2b, &ip6b2s);

bytes ports2b(const std::string&);
std::string portb2s(const bytes&);
static const transcoder port_transcoder(&ports2b, &portb2s);

bytes ipfss2b(const std::string&);
std::string ipfsb2s(const bytes&);
static const transcoder ipfs_transcoder(&ipfss2b, &ipfsb2s);


enum protocodes
{
	P_IP4   = 0x0004,
	P_TCP   = 0x0006,
	P_UDP   = 0x0111,
	P_DCCP  = 0x0021,
	P_IP6   = 0x0029,
	P_QUIC  = 0x01CC,
	P_SCTP  = 0x0084,
	P_UDT   = 0x012D,
	P_UTP   = 0x012E,
	P_UNIX  = 0x0190,
	P_IPFS  = 0x01A5,
	P_HTTP  = 0x01E0,
	P_HTTPS = 0x01BB,
	P_ONION = 0x01BC
};

struct protocol final
{
	protocol() = default;

	explicit protocol(int _code, int _size, std::string _name, bool _path)
		: m_code(_code), m_size(_size), m_name(_name), m_path(_path), m_has_transc(false)
	{
		put_uvarint(m_vicode, _code);
	}
	explicit protocol(int _code, int _size, std::string _name, bool _path, transcoder _transcoder)
		: m_code(_code), m_size(_size), m_name(_name), m_path(_path), m_has_transc(true), m_transcoder(_transcoder)
	{
		put_uvarint(m_vicode, _code);
	}

	int m_code;
	int m_size;
	std::string m_name;
	bytes m_vicode;
	bool m_path;
	bool m_has_transc;
	transcoder m_transcoder;
};

int size_for_addr(const protocol&, const bytes&);
protocol proto_with_name(const std::string&);
protocol proto_with_code(const int&);

bytes string2bytes(std::string);
std::string bytes2string(bytes);

static const std::array<protocol, 12> protocols = {
	protocol(P_IP4, 32, "ip4", false, ip4_transcoder),
	protocol(P_TCP, 16, "tcp", false, port_transcoder),
	protocol(P_UDP, 16, "udp", false, port_transcoder),
	protocol(P_DCCP, 16, "dccp", false, port_transcoder),
	protocol(P_IP6, 128, "ip6", false, ip4_transcoder),
	protocol(P_SCTP, 16, "sctp", false, port_transcoder),
	protocol(P_IPFS, -1, "ipfs", false, ipfs_transcoder),
	protocol(P_UTP, 0, "utp", false),
	protocol(P_UDT, 0, "udt", false),
	protocol(P_QUIC, 0, "quic", false),
	protocol(P_HTTP, 0, "http", false),
	protocol(P_HTTPS, 0, "https", false)
};

}

class Addr final
{
public:
	Addr() = default;
	Addr(Addr &&) = default;
	Addr(const Addr &) = default;
	Addr &operator=(Addr &&) = default;
	Addr &operator=(const Addr &) = default;
	~Addr() = default;

	explicit Addr(const std::string& _s) : m_string(_s), m_raw(_s.begin(), _s.end()) {};
	explicit Addr(const bytes& _b) : m_raw(_b), m_string(_b.begin(), _b.end()) {};

private:
	bytes m_raw;
	std::string m_string;
};

}


#endif // !MULTIADDR_H