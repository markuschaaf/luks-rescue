#include <boost/preprocessor/seq.hpp>
#include <boost/preprocessor/tuple.hpp>

#define CLI_PARAM_READ_( i, t, ... ) \
if( !strcmp( param, #i )) cli_read( arg, i ); else
#define CLI_PARAM_READ( r, d, e ) CLI_PARAM_READ_ e

#define CLI_PARAM_DEF_( i, t, ... ) t i __VA_OPT__(= __VA_ARGS__);
#define CLI_PARAM_DEF( r, d, e ) CLI_PARAM_DEF_ e

#define CLI_PARAMS_DEF( p ) \
struct Params { \
    BOOST_PP_SEQ_FOR_EACH( CLI_PARAM_DEF, ~, p ) \
    void read( Sz param, Sz arg ) { \
        try { \
            BOOST_PP_SEQ_FOR_EACH( CLI_PARAM_READ, ~, p ) \
            die( "unknown parameter" ); \
        } \
        catch( ... ) { \
            die( "%s", param ); \
        } \
    } \
    void check(); \
} params;

#define CLI_PARAMS( p ) \
    CLI_PARAMS_DEF( p )

