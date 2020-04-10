#ifndef DIE_HPP
#define DIE_HPP
#include <stddef.h>

void die( char const *fmt, ... ) __attribute__(( format( printf, 1, 2 ) ));
size_t print_errmsg( int fd = 2 );

#endif // DIE_HPP
