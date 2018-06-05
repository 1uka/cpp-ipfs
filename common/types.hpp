/**
 * @brief Header containing most commonly used types
 * 
 * @file types.hpp
 * @author Luka Atanasovski
 * @date 2018-05-20
 */

#pragma once


#include <vector>
#include <string>

#include <boost/asio/ip/address.hpp>

#include "exception.hpp"

using byte  = uint8_t;
using bytes = std::vector<byte>;

using ipaddr = boost::asio::ip::address;
using ip4addr = boost::asio::ip::address_v4;
using ip4bytes = ip4addr::bytes_type;
using ip6addr = boost::asio::ip::address_v6;
using ip6bytes = ip6addr::bytes_type;