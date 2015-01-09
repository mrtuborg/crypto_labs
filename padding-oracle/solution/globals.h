#ifndef GLOBALS_H
#define GLOBALS_H

#include <errno.h>

extern int verbose;

#define CODE(x)         do{ x; }while(0);
#define DEBUG(x...)        if (verbose) CODE(printf(x))
#define VERBOSE(y,x...) if (verbose) { CODE(printf(x)); CODE(y); }


#define BLOCK_SIZE   (16)

#endif