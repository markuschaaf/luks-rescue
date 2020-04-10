#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>

static int secSz;
static uint64_t devSz;

int main( int argc, char** argv )
{
    int dev = argc >= 2 ? open( argv[1], O_RDWR | O_NOCTTY | O_CLOEXEC ) : 1;
    if( dev < 0 ) error( 1, errno, "open( %s, O_RDWR | O_NOCTTY | O_CLOEXEC )", argv[1] );
    if( ioctl( dev, BLKSSZGET, &secSz )) error( 1, errno, "ioctl( %d, BLKSSZGET, %p )", dev, &secSz );
    fprintf( stderr, "sector size: %d\n", secSz );
    if( ioctl( dev, BLKGETSIZE64, &devSz )) error( 1, errno, "ioctl( %d, BLKGETSIZE64, %p )", dev, &devSz );
    fprintf( stderr, "device size: %ju\n", (uintmax_t) devSz );
    uint8_t buf[ secSz ];
    memset( buf, 0, secSz );
    int lastperc = -1;
    for( uint_fast64_t i = 0, j = devSz / secSz; i < j; ++i ) {
        for( unsigned k = 0; k < 8; ++k ) buf[k] = i >> 8 * k;
        ssize_t r = write( dev, buf, secSz );
        if( r == -1 ) error( 1, errno, "write" );
        if( r != secSz ) error( 1, 0, "short write" );
        int perc = 100.0 * ( i + 1 ) / j;
        if( perc > lastperc ) fprintf( stderr, "written: %d%%\r", perc );
    }
    fprintf( stderr, "\n" );
}
