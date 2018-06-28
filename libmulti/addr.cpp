#include "addr.hpp"

#include <common/varint.hpp>

#include <boost/algorithm/string.hpp>

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
    bytes b;
    put_varint(b, i);
    return b;
}

std::string portb2s(const bytes& b)
{
    if(b.size() > 2) { return ""; }
    return std::to_string(varint(b));
}


bytes ipfss2b(const std::string& s)
{
    try
    {
        bytes _hash = multi::base::b58btc_decode(s);
        bytes b(_hash.begin() + 2, _hash.end());
        put_uvarint(b, b.size());
        return b;
    } catch(const Exception& e)
    {
        throw e;
    }
}

std::string ipfsb2s(const bytes& b)
{
    int len;
    size_t size;
    size = uvarint(b, &len);
    bytes hash(b.begin() + len, b.end());
    if(hash.size() != size) { throw Exception("inconsistent lengths"); }
    put_uvarint(hash, multi::hash::sha2_256.len());
    put_uvarint(hash, multi::hash::sha2_256.code());
    return multi::base::b58btc_encode(hash);
}


protocol proto_with_name(const std::string& s)
{
    for(size_t i = 0; i < protocols.size(); i++)
    {
        if(protocols[i].m_name == s) { return protocols[i]; }
    }
    return protocol();
}

protocol proto_with_code(const int& c)
{
    for(size_t i = 0; i < protocols.size(); i++)
    {
        if(protocols[i].m_code == c) { return protocols[i]; }
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

        put_varint(buf, p.m_code, VINT_SUFFIX);
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

        uint64_t size = size_for_addr(p, b);
        if(b.size() < size)
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

uint64_t size_for_addr(const protocol& p, const bytes& b)
{
    if(p.m_size > 0) {
        return p.m_size / 8;
    } else if(p.m_size == 0) {
        return 0;
    } else {
        int n;
        uint64_t x = uvarint(b, &n);
        if(n <= 0) return 0;
        return x + n;
    }
}


std::vector<bytes> bytes_split(bytes b)
{
    std::vector<bytes> ret;
    while(b.size() > 0)
    {
        int code, len;
        size_t size;
        code = varint(b, &len);
        protocol p = proto_with_code(code);
        if(p.m_code == 0)
        {
            throw Exception("no protocol with that code");
        }

        size = size_for_addr(p, b);
        len += size;
        if(b.size() <= (size_t) len)
        {
            ret.push_back(bytes(b.begin(), b.end()));
            return ret;
        } else
        {
            ret.push_back(bytes(b.begin(), b.begin() + len));
            b.erase(b.begin(), b.begin() + len);
        }
    }
    
    return ret;
}


}

std::vector<Addr> Addr::split() const
{
    std::vector<bytes> bs;
    try
    {
        bytes raw = this->raw();
        bs = addr::bytes_split(raw);
    } catch(const Exception& e)
    {
        throw e;
    }
    std::vector<Addr> addrs(bs.size());
    
    for(auto&& a : bs)
    {
        addrs.push_back(Addr(a));
    }
    
    return addrs;
}


std::vector<addr::protocol> Addr::protocols() const
{
    std::vector<addr::protocol> protos;
    bytes buf = this->m_raw;
    while(buf.size() > 1)
    {
        int code, len, size;
        code = varint(buf, &len);

        addr::protocol p = addr::proto_with_code(code);
        if(p.m_code == 0)
        {
            throw Exception("multiaddress has invalid protocol code");
        }

        protos.push_back(p);
        buf.erase(buf.begin(), buf.begin() + len);

        size = addr::size_for_addr(p, buf);
        buf.erase(buf.begin(), buf.begin() + size);
    }

    return protos;
}

std::string Addr::value_for_proto(const int& code) const
{
    std::vector<Addr> addrs = this->split();
    for(auto&& sub : addrs)
    {
        if(sub.string() == "") continue;
        addr::protocol p = sub.protocols()[0];
        if(p.m_code == code)
        {
            if(p.m_size == 0) return "";
            std::vector<std::string> res;
            std::string s = sub.string();
            boost::split(res, s, [](char c) { return c == '/';});
            return res.back();
        }
    }
    
    return "";
}


Addr Addr::encapsulate(const Addr& o)
{
    bytes mb = this->m_raw;
    bytes ob = o.raw();
    mb.insert(mb.end(), ob.begin(), ob.end());
    return Addr(mb);
}

Addr Addr::decapsulate(const Addr& o)
{
    std::string s1 = this->m_string;
    std::string s2 = o.string();

    size_t i = s1.rfind(s2);
    if(i == std::string::npos)
    {
        return Addr(*this);
    }

    return Addr(std::string(s1.begin(), s1.begin() + i));
}


}
