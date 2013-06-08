#include "config.h"

#include "log.h"
#include "arch/platform.h"

#include <stdio.h>
#include <stdarg.h>

static bool log_flush=false;
int log_level=0;
static FILE *debug_log;

bool init_log( const char * file_name, bool flush )
{
    if( debug_log==NULL ) {
        debug_log=fopen(file_name, "at");

        if( debug_log==NULL ) {
            perror("fakeroot-ng: Could not open debug log");

            return false;
        } else {
            log_level=1;
        }

        log_flush=flush;
    }

    return true;
}

void close_log()
{
    if( debug_log!=NULL )
        fclose(debug_log);
}

void __dlog_( const char *format, ... )
{
    if( debug_log!=NULL ) {
        if( format!=NULL ) {
            va_list params;

            va_start(params, format);
            vfprintf(debug_log, format, params);
            va_end(params);
        }
        if( format==NULL || log_flush ) {
            fflush( debug_log );
        }
    }
}

int get_log_fd()
{
    if( debug_log!=NULL )
        return fileno(debug_log);
    else
        return -1;
}
