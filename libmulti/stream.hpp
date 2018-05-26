#pragma once

#include <common/types.hpp>
#include <common/varint.hpp>
#include <common/channel.hpp>

#include <iostream>
#include <thread>

namespace multi {

/**
 * @brief Multistream interface class
 * 
 */
class Stream
{
public:
	Stream() = default;
	virtual ~Stream() = default;

	virtual int read(bytes&) = 0;
	virtual int write(const bytes&) = 0;
};


namespace stream {

static std::string const proto_id = "/multistream/1.0.0";


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

	multi::Stream* negotiate_lazy(std::iostream&);
	void negotiate();

private:
	std::mutex handler_lock;
	std::vector<Handler> handlers;

	void __remove_handler(const std::string&);
	Handler* __find_handler(const std::string&);
};


class lazy_srv : public multi::Stream
{
public:
	explicit lazy_srv(std::iostream& _rw) : multi::Stream(), rw(_rw) {};

	static std::once_flag wait_flag;
	inline static void wait_for_handshake(std::function<void()> f) { std::call_once(lazy_srv::wait_flag, f); };

	int read(bytes&);
	int write(const bytes&);

private:
	std::iostream& rw;
};


void delim_write(std::ostream&, const bytes&);
bytes lp_read_buf(std::istream&);
std::vector<std::string> ls(std::iostream&);

std::string read_next_token(std::iostream&);
bytes read_next_token_bytes(std::iostream&);

}
}