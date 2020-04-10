#include "die.hpp"
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <sys/uio.h>
#include <string.h>
#include <stdlib.h>

#define ARR_SZ( a ) ( sizeof( a ) / sizeof( (a)[0] ))

class ErrMsg {
    char *parts[32]; // size <= IOV_MAX / 2
    char **parts_beg;
    char **parts_end() { return parts + ARR_SZ( parts ); }
    static char *elipsis() { return (char*) "..."; }
    static char *missing() { return (char*) "???"; }
    static void free_slot( char *slot );
public:
    ErrMsg() : parts_beg( parts_end() ) {}
    void clear();
    ~ErrMsg() { clear(); }
    void format( int err, char const *fmt, va_list args );
    size_t print( int fd = 2 );
};

class Die {};

void ErrMsg::free_slot( char *slot )
{
    if( slot != elipsis() && slot != missing() ) {
        free( slot );
    }
}

void ErrMsg::clear()
{
    while( parts_beg != parts_end() ) free_slot( *parts_beg++ );
}

void ErrMsg::format( int err, char const *fmt, va_list args )
{
    if( parts_beg == parts ) {
        if( parts[3] != elipsis() ) { free_slot( parts[3] ); parts[3] = elipsis(); }
    } else {
        --parts_beg;
    }
    errno = err;
    if( vasprintf( parts_beg, fmt, args ) < 0 ) *parts_beg = missing();
}

static void iov_push( iovec *&iop, char *str )
{
    iop->iov_base = str;
    iop->iov_len = strlen( str );
    ++iop;
}

size_t ErrMsg::print( int fd )
{
    size_t written = 0;
    iovec iov[ 2 * ARR_SZ( parts ) ], *iop = iov;
    for( char **p = parts_beg; ; ) {
        iov_push( iop, *p );
        if( ++p == parts_end() ) break;
        iov_push( iop, (char*) ": " );
    }
    iov_push( iop, (char*) "\n" );
    if( ssize_t r = writev( fd, iov, iop - iov ); r > 0 )
        written += (size_t) r;
    clear();
    return written;
}

static thread_local ErrMsg err_msg;

void die( char const *fmt, ... )
{
    int err = errno;
    va_list args;
    va_start( args, fmt );
    err_msg.format( err, fmt, args );
    va_end( args );
    throw Die();
}

size_t print_errmsg( int fd )
{
    return err_msg.print( fd );
}

