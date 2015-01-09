#ifndef UI_H
#define UI_H

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h> 

#include <globals.h>

extern void keybreak(int sig);
extern void dbldim_array_print(       unsigned char  *dbldim_array,
								const unsigned int     block_start,
								const unsigned int    blocks_count,
								const unsigned int     block_size);

extern void print_hex_vector(   const unsigned char *array,
								const unsigned int   size);

extern void print_char_vector(  const unsigned char *array,
								const unsigned int   size);


extern int print_plain(       unsigned char *plain,
						const unsigned int block_size,
						const unsigned int IV_index);

extern int print_pad_sample(    const unsigned int pad,
								const unsigned int block_size);
								
extern int print_2ndpart(       const unsigned int start,
								const unsigned int block_size,
								const unsigned char* array);

extern int get_lineopts(int argc, char *argv[]);

#endif