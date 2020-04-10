#include "die.hpp"
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <type_traits>
#include <limits>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <nettle/gcm.h>
#include <string.h>

using namespace std;

typedef uint8_t Byte;
typedef char const* Sz;

struct File {
    typedef make_unsigned_t< off_t > Size;
    Sz name;
    int fd;
    void fatal() const { die( "%s: %m", name ); }
    File( File const& ) = delete;
    File& operator=( File const& ) = delete;
    ~File() { if( close( fd )) fatal(); }
    File( Sz name, int flags );
    void stat( struct stat &st ) const { if( fstat( fd, &st )) fatal(); }
    struct Stat : stat {
        Stat( File const& file ) { file.stat( *this ); }
        Size size() const { return st_size; }
    };
};

File::File( Sz name, int flags )
:   name( name ),
    fd( open( name, flags | O_CLOEXEC | O_NOCTTY, 0666 ))
{
    if( fd < 0 ) fatal();
}

struct InFile : File {
    InFile( Sz name ) : File( name, O_RDONLY ) {}
};

struct OutFile : File {
    OutFile( Sz name ) : File( name, O_WRONLY | O_CREAT | O_TRUNC ) {}
    void write( Byte const* buf, size_t sz ) const;
};

void OutFile::write( Byte const* buf, size_t sz ) const
{
    while( sz ) {
        ssize_t r = ::write( fd, buf, sz );
        if( r == -1 ) {
            if( errno != EAGAIN && errno != EINTR ) fatal();
        } else {
            buf += (size_t) r;
            sz -= (size_t) r;
        }
    }
}

struct RoMapping {
    Byte const *data;
    size_t size;
    RoMapping( InFile const& file );
    ~RoMapping() { if( munmap( (void*) data, size )) die( "munmap(%p,%zx): %m", data, size ); }
};

RoMapping::RoMapping( InFile const& file )
{
    File::Size fsz = File::Stat( file ).size();
    if( fsz > SIZE_MAX ) die( "%s: too big to mmap", file.name );
    size = fsz;
    void *pa = mmap( nullptr, size, PROT_READ, MAP_SHARED, file.fd, 0 );
    if( pa == MAP_FAILED ) file.fatal();
    data = (Byte const *) pa;
}

struct Argv {
    struct Lazy {
        Sz arg, title;
        uintmax_t getUint( uintmax_t max ) const;
        template< class U > operator U() const {
            static_assert( is_integral_v< U > && is_unsigned_v< U > );
            if constexpr( is_integral_v< U > && is_unsigned_v< U > ) return getUint( numeric_limits< U >::max() );
        }
        operator Sz() const { return arg; }
        Lazy( Sz arg, Sz title ) : arg( arg ), title( title ) {}
    };
    template< class T >
    struct LazyDef {
        Lazy lazy;
        T def;
        template< class U > operator U() const { return lazy.arg ? lazy : def; }
        LazyDef( Sz arg, Sz title, T def ) : lazy( arg, title ), def( def ) {}
    };
    char** argv_;
    Argv( char** argv ) : argv_( argv ) { if( !*argv_ ) die( "missing argv[0]" ); ++argv_; }
    ~Argv() { while( *argv_ ) fprintf( stderr, "extra argument ignored: %s\n", *argv_++ ); }
    Lazy operator()( Sz title ) { if( !*argv_ ) die( "%s missing", title ); return { *argv_++, title }; }
    LazyDef< uintmax_t > operator()( Sz title, uintmax_t def ) { return { *argv_ ? *argv_++ : nullptr, title, def }; }
};

uintmax_t Argv::Lazy::getUint( uintmax_t max ) const
{
    char* end;
    errno = 0;
    uintmax_t val = strtoull( arg, &end, 0 );
    if( !errno && *end != '\0' ) errno = EINVAL;
    if( !errno && val > max ) errno = ERANGE;
    if( errno ) die( "%s: %m", title );
    return val;
}

struct AesGcm {
    static constexpr size_t digestSz = GCM_DIGEST_SIZE;
    static constexpr size_t ivSz = GCM_IV_SIZE;
    gcm_aes_ctx ctx;
    AesGcm( Byte const* key, size_t keyLen ) { gcm_aes_set_key( &ctx, keyLen, key ); }
    void setIV( Byte const* iv ) { gcm_aes_set_iv( &ctx, ivSz, iv ); }
    void addAAD( Byte const* aad, size_t aadLen ) { gcm_aes_update( &ctx, aadLen, aad ); }
    void encrypt( Byte const* src, size_t len, Byte* dst ) { gcm_aes_encrypt( &ctx, len, dst, src ); }
    void decrypt( Byte const* src, size_t len, Byte* dst ) { gcm_aes_decrypt( &ctx, len, dst, src ); }
    void getDigest( Byte* digest ) { gcm_aes_digest( &ctx, digestSz, digest ); }
};

struct LuksAesGcmPlain : AesGcm {
    Byte const *imgBeg, *imgEnd;
    size_t secCnt, secSz, offset, secPerArea, metaSz, areaSz;
    LuksAesGcmPlain( Byte const* img, size_t imgSz, Byte const* key, size_t keySz, size_t secCnt, size_t secSz );
    unsigned findOffset( size_t alignSz, unsigned minCert );
    void rescue( OutFile const& of );
    unsigned canDecrypt();
    unsigned canDecryptArea( size_t area );
    void initCrypt( size_t secIdx );
};

LuksAesGcmPlain::LuksAesGcmPlain(
    Byte const* img, size_t imgSz,
    Byte const* key, size_t keySz,
    size_t secCnt, size_t secSz
)
:   AesGcm( key, keySz ),
    imgBeg( img ), imgEnd( img + imgSz ),
    secCnt( secCnt ), secSz( secSz ),
    offset( 0 ), secPerArea( 32768 / ( secSz / 512 )),
    metaSz( 128 * 1024 ), areaSz( secPerArea * secSz + metaSz )
{
}

unsigned LuksAesGcmPlain::findOffset( size_t alignSz, unsigned minCert )
{
    size_t maxOffset = size_t( imgEnd - imgBeg ) - areaSz;
    for( offset = 0; offset <= maxOffset; offset += alignSz )
        if( unsigned r = canDecrypt(); r >= minCert ) return r;
    return 0;
}

#define steps 4
#define step( a ) (( a + ( steps - 1 )) / steps )

unsigned LuksAesGcmPlain::canDecrypt()
{
    unsigned percent = 0;
    size_t areaCnt = ( size_t( imgEnd - imgBeg ) - offset ) / areaSz;
    for( size_t area = 0; area < areaCnt; area += step( areaCnt ))
        percent += canDecryptArea( area );
    return percent / steps;
}

unsigned LuksAesGcmPlain::canDecryptArea( size_t area )
{
    Byte const *meta = imgBeg + offset + area * areaSz;
    Byte const *data = meta + metaSz;
    unsigned percent = 0;
    Byte tgt[ secSz ], digest[ digestSz ];

    for( size_t i = 0; i < secPerArea; i += step( secPerArea )) {
        initCrypt(( area * secPerArea + i ) * ( secSz / 512 ));
        decrypt( data + i * secSz, secSz, tgt );
        getDigest( digest );
        if( 0 == memcmp( digest, meta + i * digestSz, digestSz ))
            percent += 100;
    }
    return percent / steps;
}

#undef step
#undef steps

void LuksAesGcmPlain::initCrypt( size_t secIdx )
{
    Byte aad[ 8 + ivSz ];
    for( unsigned i = 0; i < 8; ++i )
        aad[ i ] = aad[ i + 8 ] = secIdx >> 8 * i;
    memset( aad + 16, 0, sizeof aad - 16 );
    setIV( aad + 8 );
    addAAD( aad, sizeof aad );
}

void LuksAesGcmPlain::rescue( OutFile const& of )
{
    Byte tgt[ secSz ], digest[ digestSz ];
    size_t areaCnt = ( secCnt + ( secPerArea - 1 )) / secPerArea;

    for( size_t area = 0; area < areaCnt; ++area )
    {
        Byte const *meta = imgBeg + offset + area * areaSz;
        Byte const *data = meta + metaSz;
        size_t sec, ok = 0;

        for( sec = 0; sec < secPerArea; ++sec )
        {
            size_t absSec = area * secPerArea + sec;
            if( absSec == secCnt ) break;
            initCrypt( absSec * ( secSz / 512 ));
            decrypt( data + sec * secSz, secSz, tgt );
            getDigest( digest );
            if( 0 == memcmp( digest, meta + sec * digestSz, digestSz )) ++ok;
            of.write( tgt, secSz );
        }
        fputc(( ok ? ok == sec ? '.' : 'o' : 'O' ), stderr );
    }
    fputc( '\n', stderr );
}

int main( int , char** argv )
{
    try {
        Argv arg( argv );
        Sz imgFn = arg( "image file" ), keyFn = arg( "master key file" ), outFn( arg( "output file" ));
        size_t secCnt = arg( "sector count" ), secSz = arg( "sector size", 0x200 ), alignSz = arg( "alignment size", 0x8000 );
        unsigned minCert = arg( "minimum certainty", 25 );
        RoMapping img{ InFile{ imgFn }}, key{ InFile{ keyFn }};
        LuksAesGcmPlain luks( img.data, img.size, key.data, key.size, secCnt, secSz );
        fprintf( stderr, "searching data offset ...\n" );
        if( unsigned r = luks.findOffset( alignSz, minCert ); r ) {
            fprintf( stderr, "found offset %#zx with %u%% certainty\n", luks.offset, r );
            luks.rescue( OutFile( outFn ));
        } else
            die( "Cannot find offset." );
    }
    catch( ... ) {
        print_errmsg();
        return 1;
    }
}
