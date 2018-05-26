#include "stream.hpp"


namespace multi {
namespace stream {

std::once_flag lazy_srv::wait_flag;

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
	
	char buf[len];
	memset(buf, 0, len);
	
	size_t i = 0;
	while(is.get(buf[i++]) && i < len);
	
	if(buf[len - 1] != '\n')
	{
		std::cout << buf;
		throw Exception("message did not have trailing newline");
	}

	bytes ret(buf, buf + len - 1);
	return ret;
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


bytes read_next_token_bytes(std::iostream& rw)
{
	bytes data;
	try
	{
		data = lp_read_buf(rw);
	} catch(const Exception& e)
	{
		throw e;
	}

	return data;
}

std::string read_next_token(std::iostream& rw)
{
	bytes tok;
	try
	{
		tok = read_next_token_bytes(rw);
	} catch(const Exception& e)
	{
		throw e;
	}
	return std::string(tok.begin(), tok.end());
}


multi::Stream* Muxer::negotiate_lazy(std::iostream& rw)
{
	chan_t<std::string> pval;
	chan_t<int> started;
	int sink;
	lazy_srv* lzc = new lazy_srv(rw);
	std::thread(lazy_srv::wait_for_handshake, [&started, &pval, &rw]() -> void {
		started.close();

		delim_write(rw, bytes(proto_id.begin(), proto_id.end()));
		
		std::string proto;
		while(!pval.is_closed() && pval.pop(proto) != boost::fibers::channel_op_status::closed)
		{
			delim_write(rw, bytes(proto.begin(), proto.end()));
		}
	}).detach();
	started.pop(sink);

	std::string line;
	try
	{
		line = read_next_token(rw);
	} catch(const Exception& e)
	{
		pval.close();
		throw e;
	}

	if(line != proto_id)
	{
		throw Exception("incorrect proto version");
	}

	while(true)
	{
		try
		{
			line = read_next_token(rw);
		} catch(const Exception& e)
		{
			pval.close();
			throw e;
		}

		if(line == "ls") {
			pval.push("ls");
		} else {
			Handler* h = this->__find_handler(line);
			if(h == nullptr)
			{
				pval.push("na");
				continue;
			}

			pval.push(line);
			pval.close();
			return lzc;
		}
	}
	pval.close();
	return 0;
}

int lazy_srv::read(bytes& buf)
{
	char c;
	buf.clear();
	while(this->rw.get(c))
	{
		buf.push_back(c);
	}
	return buf.size();
}

int lazy_srv::write(const bytes& buf)
{
	this->wait_for_handshake([]() -> void { throw Exception("didn't initiate handhsake"); });
	rw << buf.data();
	return buf.size();
}

}
}