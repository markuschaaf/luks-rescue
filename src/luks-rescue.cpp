#include "die.hpp"
#include "cli.hpp"
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
    void rescue( OutFile const& df, OutFile const& tf );
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

void LuksAesGcmPlain::rescue( OutFile const& df, OutFile const& tf )
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
            df.write( tgt, secSz );
            tf.write( digest, digestSz );
        }
        fputc(( ok ? ok == sec ? '.' : 'o' : 'O' ), stderr );
    }
    fputc( '\n', stderr );
}

enum Percent : unsigned;

void cli_read( Sz arg, Sz &var )
{
    var = arg;
}

void cli_read( Sz arg, size_t &var )
{
    size_t val = 0;
    unsigned base = 10;
    if( *arg == '0' ) {
        ++arg;
        if( *arg == 'x' ) { ++arg; base = 16; }
        else base = 8;
    }
    for(;;) {
        unsigned d;
        if( *arg >= '0' && *arg <= '9' ) d = *arg - '0'; else
        if( *arg >= 'a' && *arg <= 'f' ) d = *arg - 'a'; else
        if( *arg >= 'A' && *arg <= 'F' ) d = *arg - 'A';
        else break;
        if( d >= base ) die( "bad digit '%c' (base = %u)", d, base );
        val *= base;
        val += d;
        ++arg;
    }
    if( *arg == 'K' ) { val *= size_t(1) << 10; ++arg; }
    if( *arg == 'M' ) { val *= size_t(1) << 20; ++arg; }
    if( *arg == 'G' ) { val *= size_t(1) << 30; ++arg; }
    if( *arg == 'T' ) { val *= size_t(1) << 40; ++arg; }
    if( *arg != 0 ) die( "bad format" );
    var = val;
}

void cli_read( Sz arg, Percent &var )
{
    unsigned val = 0;
    for(;;) {
        unsigned d;
        if( *arg >= '0' && *arg <= '9' ) d = *arg - '0';
        else break;
        val *= 10;
        val += d;
        ++arg;
    }
    if( arg[0] != '%' || arg[1] != 0 ) die( "bad format" );
    var = (Percent) val;
}

CLI_PARAMS(
    (( image_file       , Sz        ))
    (( master_key_file  , Sz        ))
    (( sector_count     , size_t    ))
    (( data_file        , Sz        ))
    (( tag_file         , Sz        ))
    (( sector_size      , size_t    , 0x200         ))
    (( alignment        , size_t    , 0x8000        ))
    (( certainty        , Percent   , (Percent) 25  ))
)

void cli_parse_argv( char **argv )
{
    if( !*argv ) die( "missing argv[0]" );
    while( *++argv ) {
        char *p = strchr( *argv, '=' );
        if( !p || !p[1] ) die( "%s: missing argument", *argv );
        *p++ = 0;
        params.read( *argv, p );
    }
}

void Params::check()
{
    #define need( p ) if( !p ) die( "missing %s", #p );
    need( image_file );
    need( master_key_file );
    need( sector_count );
    #undef need
    switch( sector_size ) {
        default:
            die( "bad sector_size" );
        case 0x200:
        case 0x400:
        case 0x800:
        case 0x1000:
            ;
    }
}

int main( int , char** argv )
{
    try {
        cli_parse_argv( argv );
        params.check();
        RoMapping img{ InFile{ params.image_file }}, key{ InFile{ params.master_key_file }};
        LuksAesGcmPlain luks( img.data, img.size, key.data, key.size, params.sector_count, params.sector_size );
        fprintf( stderr, "searching data offset ...\n" );
        if( unsigned r = luks.findOffset( params.alignment, params.certainty ); r ) {
            fprintf( stderr, "found offset %#zx with %u%% certainty\n", luks.offset, r );
            if( params.data_file || params.tag_file ) {
                #define def( p ) if( !p ) p = "/dev/null";
                def( params.data_file );
                def( params.tag_file );
                #undef def
                luks.rescue( OutFile( params.data_file ), OutFile( params.tag_file ));
            }
        } else
            die( "Cannot find offset." );
    }
    catch( ... ) {
        print_errmsg();
        return 1;
    }
}
