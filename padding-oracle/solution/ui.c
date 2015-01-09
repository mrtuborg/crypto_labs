#include <ui.h>

#include <stdlib.h>
#include <oracle.h>
void keybreak(int sig){ // can be called asynchronously
  printf("\n");
  Oracle_Disconnect();
  exit(1);
}

void dbldim_array_print(      unsigned char  *dbldim_array,
                        const unsigned int     block_start,
                        const unsigned int    blocks_count,
                        const unsigned int     block_size)
{
    int i, j;
    for (i=block_start; i<block_start+blocks_count; i++)
      for (j=0; j<block_size; j++)
        printf("%.2X ", dbldim_array[i*block_size+j]);
    printf("\n");
}

void print_hex_vector(const unsigned char *array,
                      const unsigned int   size)
{
      for (int j=0; j<size; j++)
      {
          printf("%.2X ", array[j]);
      }
}

void print_char_vector(const unsigned char *array,
                       const unsigned int   size)
{
      for (int j=0; j<size; j++)
      {
          if (isprint(array[j])) printf("%c", array[j]);
                           else  printf(".");
      }
}

int print_plain(unsigned char *plain,
                const unsigned int block_size,
                const unsigned int IV_index)
{
  printf("\nplain %d is: ", IV_index+1);
  print_hex_vector(&plain[IV_index*block_size], block_size);
  print_char_vector(&plain[IV_index*block_size], block_size);print_hex_vector(&plain[IV_index*block_size], block_size);

  return 0;
}

int print_pad_sample(const unsigned int pad,
                     const unsigned int block_size)
{
  for (int i = 0; i < block_size; i++)
  {
       if (i < block_size - pad) printf ("XX ");
       else printf("%.2X ", pad);
  }
  return 0;
}

extern int print_2ndpart(       const unsigned int start,
								const unsigned int block_size,
								const unsigned char* array)
{
  for (int i = 0; i < block_size; i++)
  {
       if (i < start) printf ("XX ");
       else printf("%.2X ", array[i]);
  }
  return 0;

}
int get_lineopts(int argc, char *argv[])
{
    if (argc < 2) {
      printf("Usage: %s <filename> [-v]\n",argv[0]);
      return -1;
    }

    if ( argc>2 && (!strcmp(argv[2],"-v"))) verbose = 1;

    return 0;
}
