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

std::vector<std::string> ls(std::iostream& rw)
{
	delim_write(rw, bytes({'l', 's'}));
	uint64_t n = uvarint(rw);
	std::vector<std::string> res(n);
	while(n--)
	{
		bytes val;
		try
		{
			val = lp_read_buf(rw);
		} catch(const Exception& e)
		{
			throw e;
		}
		res.push_back(std::string(val.begin(), val.end()));
	}

	return res;
}

void Muxer::add_handler(const std::string& proto, match_func match, handler_func handler)
{
	this->handler_lock.lock();
	this->__remove_handler(proto);
	this->handlers.push_back(Handler(match, handler, proto));
	this->handler_lock.unlock();
}

void Muxer::__remove_handler(const std::string& proto)
{
	for(size_t i = 0; i < this->handlers.size(); i++)
	{
		if(this->handlers[i].add_name == proto)
		{
			this->handlers.erase(this->handlers.begin() + i);
			return;
		}
	}
}

void Muxer::remove_handler(const std::string& proto)
{
	this->handler_lock.lock();
	this->__remove_handler(proto);
	this->handler_lock.unlock();
}

std::vector<std::string> Muxer::protocols()
{
	this->handler_lock.lock();
	std::vector<std::string> res;
	
	for(auto&& h : this->handlers)
	{
		res.push_back(h.add_name);
	}
	
	this->handler_lock.unlock();
	return res;
}

Handler* Muxer::__find_handler(const std::string& proto)
{
	this->handler_lock.lock();
	
	for(auto&& h : this->handlers)
	{
		if(h.match(proto)) 
		{
			return &h;
		}
	}

	return 0;
}

void Muxer::negotiate_lazy(std::iostream& rw)
{
	lazy_conn* lzc = new lazy_conn(rw);
	// TODO: async wait for handshake and stuff
}

}
}