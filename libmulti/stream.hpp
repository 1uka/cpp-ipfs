#pragma once

#include <common/types.hpp>
#include <common/varint.hpp>

#include <iostream>

namespace multi {
namespace stream {

constexpr char const proto_id[] = "/multistream/1.0.0";

typedef void (*handler_func)(const std::string&);

struct Handler final
{
	Handler() = default;
	~Handler() = default;

	handler_func handle;
	bool (*match_func)(const std::string&);
	std::string add_name;
};

struct Muxer final
{
	Muxer() = default;
	~Muxer() = default;

	std::mutex handler_lock;
	std::vector<handler_func> handlers;
};


void delim_write(std::ostream&, const bytes&);
bytes lp_read_buf(std::istream&);


}
}