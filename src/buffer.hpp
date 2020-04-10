#ifndef BUFFER_HPP
#define BUFFER_HPP
#include <stddef.h>
#include <stdlib.h>

void* alloc( size_t new_sz, void* old_ptr = nullptr );
void* alloc( size_t new_sz, size_t new_cnt, void* old_ptr = nullptr );

template< class E >
E* alloc( size_t new_sz, E* old_ptr = nullptr )
{
	return (E*) alloc( sizeof (E), new_sz, old_ptr );
}

template< class E >
struct Buffer {
	E *ptr;
    Buffer() : ptr( nullptr ) {}
    void resize( size_t new_sz ) { ptr = alloc< E >( new_sz, ptr ); }
	explicit Buffer( size_t sz ) : ptr( alloc< E >( sz )) {}
	~Buffer() { free( ptr ); }
	E& operator[]( size_t i ) { return ptr[i]; }
	operator E*() { return ptr; }
	E* release() { E* q = ptr; ptr = nullptr; return q; }
};

#endif // BUFFER_HPP
