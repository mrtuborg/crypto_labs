#ifndef DATA_H
#define DATA_H

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <globals.h>
#include <ui.h>

extern off_t fsize(const char *filename);

extern int load_file(      const char   *filename,
						unsigned char  **array,
						unsigned long   *size);
#endif
