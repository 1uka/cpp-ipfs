#pragma once

#include <boost/fiber/unbuffered_channel.hpp>
#include <boost/fiber/buffered_channel.hpp>

template<typename T>
using chan_t = boost::fibers::unbuffered_channel<T>;

template<typename T>
using chan_buffered_t = boost::fibers::buffered_channel<T>;