#pragma once


/**
 * @brief custom excepition type
 * 
 */
struct Exception
{
    Exception(const std::string& _msg) : m_msg(_msg) {};
    const char* what() const throw()
    {
        return m_msg.c_str();
    }
private:
    std::string m_msg;
};