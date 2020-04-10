#include "buffer.hpp"
#include <errno.h>
#include <error.h>
#include <sysexits.h>

void* alloc( size_t new_sz, void* old_ptr )
{
    void *p = realloc( old_ptr, new_sz );
    if( !p ) error( EX_OSERR, errno, "alloc(%zx,%p)", new_sz, old_ptr );
    return p;
}

void* alloc( size_t new_sz, size_t new_cnt, void* old_ptr )
{
	new_sz *= new_cnt;
	if( new_sz < new_cnt ) error( EX_UNAVAILABLE, 0, "alloc(%zx,%zx,%p) overflows size_t", new_sz, new_cnt, old_ptr );
	return alloc( new_sz, old_ptr );
}

