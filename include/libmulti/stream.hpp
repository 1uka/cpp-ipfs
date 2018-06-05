#pragma once

#include <common/types.hpp>

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

    Stream(std::iostream&, const std::string&);

    Stream(std::iostream& _rw) : rw(_rw) {};

    virtual int read(bytes&) = 0;
    virtual int write(const bytes&) = 0;

protected:
    std::iostream& rw;
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
    handler_func negotiate(std::iostream&, std::string&);

    void ls(std::ostream&);
    void handle(std::iostream&);

private:
    std::mutex handler_lock;
    std::vector<Handler> handlers;

    void __remove_handler(const std::string&);
    Handler* __find_handler(const std::string&);
};


class lazy_srv : public multi::Stream
{
public:
    lazy_srv() = default;
    ~lazy_srv() = default;

    explicit lazy_srv(std::iostream& _rw) : multi::Stream(_rw) {};

    static std::once_flag wait_flag;

    int read(bytes&);
    int write(const bytes&);

};

class lazy_cli : public multi::Stream
{
public:
    lazy_cli() = default;
    ~lazy_cli() = default;

    explicit lazy_cli(std::iostream& _rw, const std::string& _proto) : multi::Stream(_rw), protos({_proto})
    {
        rerr = 0;
    };

    explicit lazy_cli(std::iostream& _rw, const std::vector<std::string>& _protos) : multi::Stream(_rw), protos(_protos) 
    {
        rerr = 0;
    };

    static std::once_flag rflag;
    static std::once_flag wflag;

    int read(bytes&);
    int write(const bytes&);

    void do_read_handshake();
    void do_write_handshake();
    int do_write_handshake(const bytes&);

private:
    Exception* rerr;
    std::vector<std::string> protos;
};


inline void do_once(std::once_flag& flag, const std::function<void()>& f)
{
    std::call_once(flag, f);
}
inline std::thread do_once_async(std::once_flag& flag, const std::function<void()>& f)
{
    return std::thread([&flag, &f]{do_once(flag, f); });
}

void delim_write(bytes&, const bytes&);
inline void delim_write(bytes& buf, const std::string& s) { return delim_write(buf, bytes(s.begin(), s.end())); }
void delim_write(std::ostream&, const bytes&);
inline void delim_write(std::ostream& os, const std::string& s) { return delim_write(os, bytes(s.begin(), s.end())); }
bytes lp_read_buf(std::istream&);
std::vector<std::string> ls(std::iostream&);

std::string read_next_token(std::iostream&);
bytes read_next_token_bytes(std::iostream&);

void select_proto_or_fail(const std::string&, std::iostream&);
std::string select_one_of(const std::vector<std::string>&, std::iostream&);
void handshake(std::iostream&);
void try_select(const std::string&, std::iostream&);


}

inline Stream* NewMultistream(std::iostream& rw, const std::string& proto) { return new stream::lazy_cli(rw, proto); }
Stream* NewMSSelect(std::iostream&, const std::string&);

}