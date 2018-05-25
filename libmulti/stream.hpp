#pragma once

#include <common/types.hpp>
#include <common/varint.hpp>
#include <common/channel.hpp>

#include <iostream>
#include <thread>

namespace multi {
namespace stream {

constexpr char const proto_id[] = "/multistream/1.0.0";


using match_func 		= std::function<bool(const std::string&)>;
using handler_func 	= std::function<void(const std::string&, std::iostream&)>;

inline match_func fulltext_match(const std::string& s)
{
	return [&s](const std::string& m) -> bool { return s == m; };
}

struct Handler final
{
public:
	Handler() = default;
	~Handler() = default;

	explicit Handler(match_func _m, handler_func _h, const std::string& _s) 
		: match(_m), handle(_h), add_name(_s) {};

	match_func match;
	handler_func handle;
	std::string add_name;
};

class Muxer final
{
public:
	Muxer() = default;
	~Muxer() = default;

	void add_handler(const std::string&, match_func, handler_func);
	inline void add_handler(const std::string& s, handler_func handler) 
	{
		add_handler(s, fulltext_match(s), handler);
	}

	void remove_handler(const std::string&);
	std::vector<std::string> protocols();

	void negotiate_lazy(std::iostream&);
	void negotiate();

private:
	std::mutex handler_lock;
	std::vector<Handler> handlers;

	void __remove_handler(const std::string&);
	Handler* __find_handler(const std::string&);
};


struct lazy_conn
{
	explicit lazy_conn(std::iostream& _rw) : rw(_rw) {};

	static std::once_flag wait_flag; // watch out for this, might cause some bug
	std::iostream& rw;

	inline static void wait_for_handshake(std::function<void()> f) { std::call_once(wait_flag, f); };
};


void delim_write(std::ostream&, const bytes&);
bytes lp_read_buf(std::istream&);
std::vector<std::string> ls(std::iostream&);

std::string read_next_token(std::iostream&);
bytes read_next_token_bytes(std::iostream&);

}
}