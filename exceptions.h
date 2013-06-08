#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <exception>
#include <errno.h>
#include <string.h>

class errno_exception : public std::exception 
{
    int _errno;
    const char * _context;
public:
    errno_exception( const char * context ) :
        _errno( errno ), _context( context )
    {}

    const char * what() const throw()
    {
        return _context;
    }

    int get_error() const throw()
    {
        return _errno;
    }

    const char *get_error_message() const throw()
    {
        return strerror(_errno);
    }
};

class detailed_exception : public std::exception
{
    const char * _message;
public:
    detailed_exception( const char * message ) : _message( message )
    {}

    const char * what() const throw()
    {
        return _message;
    }
};

#endif // EXCEPTIONS_H
