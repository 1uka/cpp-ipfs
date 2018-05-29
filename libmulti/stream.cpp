#include "stream.hpp"

#include <common/varint.hpp>
#include <common/channel.hpp>


namespace multi {
namespace stream {

std::once_flag lazy_srv::wait_flag;
std::once_flag lazy_cli::rflag;
std::once_flag lazy_cli::wflag;

void delim_write(bytes& buf, const bytes& mes)
{
	put_uvarint(buf, mes.size() + 1);
	buf.insert(buf.end(), mes.begin(), mes.end());
	buf.push_back('\n');
}

void delim_write(std::ostream& os, const bytes& mes)
{
	put_uvarint(os, mes.size() + 1);
	os.write((const char*) mes.data(), mes.size());
	os << '\n';
}

bytes lp_read_buf(std::istream& is)
{
	uint64_t len = uvarint(is);
	if(len > (64 << 10))
	{
		throw Exception("incoming message too large");
	}

	char buf[len];
	memset(buf, 0, sizeof(buf));
	is.read(buf, sizeof(buf));
	
	if(buf[len - 1] != '\n')
	{
		throw Exception("message did not have trailing newline");
	}

	bytes ret(buf, buf + len - 1);
	return ret;
}

std::vector<std::string> ls(std::iostream& rw)
{
	delim_write(rw, "ls");
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
			this->handler_lock.unlock();
			return &h;
		}
	}

	this->handler_lock.unlock();
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

	do_once_async(lazy_srv::wait_flag, [&started, &pval, &rw] {
		started.close();

		delim_write(rw, proto_id);
		
		std::string proto;
		while(!pval.is_closed() && pval.pop(proto) != boost::fibers::channel_op_status::closed)
		{
			delim_write(rw, proto);
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
		pval.close();
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
}

handler_func Muxer::negotiate(std::iostream& rw, std::string& _p)
{
	delim_write(rw, proto_id);

	std::string line = read_next_token(rw);
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
			throw e;
		}

		if(line == "ls") {
		} else {
			Handler* h = this->__find_handler(line);
			if(h == nullptr)
			{
				delim_write(rw, "na");
				continue;
			}

			delim_write(rw, line);
			_p = line;
			return h->handle;
		}
	}
}

void Muxer::ls(std::ostream& os)
{
	bytes buf;
	this->handler_lock.lock();
	put_uvarint(buf, this->handlers.size());

	
	for(auto&& h : this->handlers)
	{
		delim_write(buf, h.add_name);
	}

	this->handler_lock.unlock();
	bytes ll(16);
	int nw = put_uvarint(ll, buf.size());
	ll.erase(buf.begin() + nw, buf.end());
	ll.insert(ll.end(), buf.begin(), buf.end());
	std::copy(
		ll.begin(),
		ll.end(),
		std::ostream_iterator<byte>(os)
	);
}

void Muxer::handle(std::iostream& rw)
{
	std::string p;
	handler_func h = this->negotiate(rw, p);
	return h(p, rw);
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
	do_once(lazy_srv::wait_flag, []() -> void { throw Exception("didn't initiate handhsake"); });
	rw.write((const char*) buf.data(), buf.size());
	return buf.size();
}

int lazy_cli::read(bytes& buf)
{
	do_once(lazy_cli::wflag, [this]{
		do_once_async(lazy_cli::wflag, [this]{ this->do_write_handshake(); }).detach();
		this->do_read_handshake();
	});

	if(this->rerr != NULL)
	{
		Exception e(this->rerr->what());
		delete this->rerr;
		throw e;
	}

	char c;
	buf.clear();
	while(this->rw.get(c))
	{
		buf.push_back(c);
	}
	
	return buf.size();
}

void lazy_cli::do_read_handshake()
{
	for(auto&& p : this->protos)
	{
		std::string tok = read_next_token(this->rw);
		if(p != tok)
		{
			this->rerr = new Exception("protocl mismatch");
			return;
		}
	}
}

int lazy_cli::do_write_handshake(const bytes& buf)
{	
	for(auto&& p : this->protos)
	{
		delim_write(this->rw, p);
	}

	int n = 0;
	if(buf.size() > 0)
	{
		this->rw.write((const char*) buf.data(), buf.size());
	}
	return n;
}

void lazy_cli::do_write_handshake()
{
	this->do_write_handshake(bytes());
}

int lazy_cli::write(const bytes& buf)
{
	int n = 0;
	do_once_async(lazy_cli::wflag, [&]{
		do_once_async(lazy_cli::rflag, [this]{ this->do_read_handshake(); }).detach();
		n = this->do_write_handshake(buf);
	}).detach();

	this->rw.write((const char*) buf.data(), buf.size());
	return buf.size();
}

void select_proto_or_fail(const std::string& proto, std::iostream& rw)
{
	try
	{
		handshake(rw);
		try_select(proto, rw);
	} catch(const Exception& e)
	{
		throw e;
	}
}

std::string select_one_of(const std::vector<std::string>& protos, std::iostream& rw)
{
	try
	{
		handshake(rw);
	} catch(const Exception& e)
	{
		throw e;
	}

	
	for(auto&& p : protos)
	{
		try
		{
			try_select(p, rw);
		} catch(const Exception& e)
		{
			throw e;
		}
		return p;
	}
	return "";
}


void handshake(std::iostream& rw)
{
	std::string tok = read_next_token(rw);
	if(tok != proto_id)
	{
		throw Exception("mismatch in protocol id");
	}

	delim_write(rw, proto_id);
}

void try_select(const std::string& proto, std::iostream& rw)
{
	delim_write(rw, proto);
	std::string tok = read_next_token(rw);

	if(tok == "na"){
		throw Exception("proto not supported");
	} else if(tok == proto) {
		return;
	} else {
		throw Exception("unrecognized response");
	}
}

}

Stream* NewMSSelect(std::iostream& rw, const std::string& proto)
{
	std::vector<std::string> vec({stream::proto_id});
	vec.push_back(proto);
	return new stream::lazy_cli(rw, vec);
}


}