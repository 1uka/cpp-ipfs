#include "stream.hpp"


namespace multi {
namespace stream {


void delim_write(std::ostream& os, const bytes& mes)
{
	put_uvarint(os, mes.size() + 1);
	os << mes.data() << '\n';
}

bytes lp_read_buf(std::istream& is)
{
	uint64_t len = uvarint(is);
	if(len > (64 << 10))
	{
		throw Exception("incoming message too large");
	}
	
	bytes buf(len);
	is.get((char*) buf.data(), len); // TODO: this might cause a bug
	if(buf.size() == 0 || buf.back() != (byte) '\n') // FIXME: somehow the newline char gets lost/formatted
	{
		throw Exception("message did not have trailing newline");
	}

	buf.pop_back();
	return buf;
}


}
}