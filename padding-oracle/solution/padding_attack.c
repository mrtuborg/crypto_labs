#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <signal.h> 
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>

int verbose = 0;

void keybreak(int sig){ // can be called asynchronously
  printf("\n");
  Oracle_Disconnect();
  exit(1);
}
// Read a ciphertext from a file, send it to the server, and get back a result.
// If you run this using the challenge ciphertext (which was generated correctly),
// you should get back a 1. If you modify bytes of the challenge ciphertext, you
// may get a different result...

// Note that this code assumes a 3-block ciphertext.

  #define BLOCK_SIZE   (16)
  //#define CTEXT_LENGTH (48)
  //#define BLOCKS_COUNT (CTEXT_LENGTH/BLOCK_SIZE)

 /* unsigned char cipher[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char _cipher[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char interm[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char  plain[BLOCKS_COUNT][BLOCK_SIZE] = {0};
*/

off_t fsize(const char *filename) {
    struct stat st;

    if (stat(filename, &st) == 0)
        return st.st_size;

    fprintf(stderr, "Cannot determine size of %s: %s\n",
            filename, strerror(errno));

    return -1;
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

int load_file(   const char   *filename,
               unsigned char  **array,
               unsigned long   *size)
{
  FILE *fpIn;
  unsigned int tmp;

  *size = fsize(filename);
  if (*size == -1) return -1;
  *array = malloc(*size);
  fpIn = fopen(filename, "r");

  for(unsigned long i=0; i<*size; i++) {
    fscanf(fpIn, "%02x", &tmp);
    (*array)[i] = (unsigned char)tmp;
  }

  fclose(fpIn);
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

unsigned char alg_find_CBC_padding_value(      unsigned char *ctext,
                                         const unsigned int   block_size,
                                         const unsigned int   blocks_count)
{
       int ret                      = 0;    // Oracle responces
  unsigned int             IV_index = 0;    // Will iterate from 0,1... until found padded message
  unsigned int not_padded_bytes_pos = 0;

  Oracle_Connect();
  do           // Trying each cipher block as IV vector for the next block
  {
    printf("\nConsider block C%d has padding\n", IV_index+1);
    for (int i=0; i<block_size; i++)
    {
      ctext[IV_index*block_size + i] = ctext[IV_index*block_size + i] + 1; 
      ret = Oracle_Send((unsigned char*)&ctext[IV_index*block_size], 2); // the first argument is an unsigned char array ctext;
                                                                        // the second argument indicates how many blocks ctext has
      if ((ret == 0) && (i == 0))
      {
          printf("All message padded?\n");
          break;
      } else {
        if (verbose) printf("Changed %d-th element in C%d, oracle returned: %d\n", i, IV_index, ret);
        if (ret == 0) {
            not_padded_bytes_pos = i;
            break;
        }
      }
    }
    if (not_padded_bytes_pos == 0) printf("\nBlock C%d has no padding\n", IV_index+1);
  } while ((not_padded_bytes_pos == 0) && (++IV_index < (blocks_count - 1)));
  
  Oracle_Disconnect();
  return block_size - not_padded_bytes_pos;
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

int alg_padding_forgery(      unsigned char  new_pad,
                              unsigned char *ctext,
                        const unsigned int   block_size,
                        const unsigned int   IV_index)
{
  int DByte = -1;
  int ret   =  0;

  Oracle_Connect();
  for (int i = 0; i <= 0xFF; i++) // guess loop
  {
    ctext[IV_index*block_size + block_size - new_pad] = i; // BLOCK_SIZE-new_pad: 16 - 12: 4
    if (verbose)
    {
      printf("\n new C%d is: ", IV_index);
      print_hex_vector(&ctext[IV_index*block_size], block_size);

    }

    ret = Oracle_Send((unsigned char*)&ctext[IV_index*block_size], 2);
    if (verbose) printf(", ret = %d", ret);
    if (ret == 1) 
    {
      DByte = i;
      break;
    }
  }
  Oracle_Disconnect();
  if (ret == 0)
  {
   printf("\nPadding oracle attack failed!\n");
   return -1;
  }

  return DByte;
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
                     const unsigned int block_size,
                     const unsigned int IV_index)
{
  printf("\n\nC%d padding: ", IV_index);
  for (int i = 0; i < block_size; i++)
  {
       if (i < block_size - pad) printf ("XX ");
       else printf("%.2X ", pad);
  }
  return 0;
}

int alg_find_plaintext_byte_by_padding_forge(const unsigned char  pad,
                                                             unsigned char* ctext,
                                                       const unsigned int   block_size,
                                                       const unsigned int   IV_index)
{



  int new_pad=pad;
  unsigned char DByte = 0;

  while (new_pad < BLOCK_SIZE)
  {
    //if (new_pad > pad) cipher[IV_index][BLOCK_SIZE - new_pad] = DByte ^ (new_pad) ^ (new_pad+1);
    //else cipher[IV_index][BLOCK_SIZE - new_pad] = _cipher[IV_index][BLOCK_SIZE - new_pad] ^ pad ^ new_pad+1;

    new_pad++;
    for (int i = 1; i <= pad; i++) // i: [1..11], BLOCK_SIZE-i: [15...5]
    {
      ctext[IV_index*block_size + block_size - i] = ctext[IV_index*block_size + block_size - i] ^ pad ^ new_pad;
      // Katz: 9F  =  9E   ^ 0x06    ^   0x07
      //                    old pad     new pad
    }
    
    for (int i = pad+1; i < new_pad; i++)
      ctext[IV_index*block_size + block_size - i] ^= (new_pad-1) ^(new_pad);

    for (int i = new_pad; i <= BLOCK_SIZE; i++) // i: [13..16], BLOCK_SIZE-i: [3...0]
    {
      ctext[IV_index*block_size + block_size - i] = ctext[IV_index*block_size + block_size - i];
      // Katz: 9F  =  9E   ^ 0x06    ^   0x07
      //                    old pad     new pad
    }

    print_pad_sample(new_pad, block_size, IV_index+1);

    int forgery_result = alg_padding_forgery(new_pad, ctext, block_size, IV_index);
    if (forgery_result == -1) return -1;
    else DByte = forgery_result;
   
    // I2 = C1´ ^  P2´
    //-  interm[IV_index+1][BLOCK_SIZE - new_pad] = DByte ^ new_pad;
    // P2 = C1 ^ I2
    //-   plain[IV_index+1][BLOCK_SIZE - new_pad] = _cipher[IV_index][BLOCK_SIZE - new_pad] ^ interm[IV_index+1][BLOCK_SIZE - new_pad];

    //-print_plain(plain, block_size, IV_index+1);

  }

  return 0;
}


int main(int argc, char *argv[]) {
  unsigned long  ctext_length;
  unsigned char *ctext;
 
  
  if (get_lineopts(argc, argv) == -1) return -1;
  if (load_file(argv[1], &ctext, &ctext_length) == -1) return -1;
  if (verbose) printf("DEBUG mode: verbose turned on\n");
  
  printf("\nChallenge is:\n");
  dbldim_array_print(ctext, 0, 1, BLOCK_SIZE);
  dbldim_array_print(ctext, 1, 1, BLOCK_SIZE);
  dbldim_array_print(ctext, 2, 1, BLOCK_SIZE);

   // Register signals to close Oracle whenever we want by Ctrl+C
  signal(SIGINT, keybreak); 
  

  int i, tmp, ret;

  int IV_index = 0;
  int not_padded_bytes_pos = 0;

  // STEP 1
  // Looking for padding length
  // Will change IV to find misformated PKCS#7 string
  //

int pad = alg_find_CBC_padding_value(ctext, BLOCK_SIZE, ctext_length/BLOCK_SIZE);
print_pad_sample(pad, BLOCK_SIZE, IV_index+1);


// prof Katz explanation:
// Observation:
//    Plaintext  =  Dec(k,c) ^ IV
//        =>  IV[i]´ -> PlainText[i]´
// 1) Padding guess -> try to spoil padding, by spoiling bytes in IV from 0...[size of IV]
//    pad = 0x0B
//
// 2) for i: [size of IV] ... [size of IV  -  pad]  :   Plain[i] = IV[i] ^ pad ^ X
//                                  --> new padding 0x0C -> 0x0C = IV[i] ^ 0x0B ^ X
//                                  --> IV[i]´ = IV[i]^X = 0x0C ^ 0x0B                    Oracle = fail
//
// 3) for i = [size of IV  -  new pad] = [size of IV  -  0x0C] = 0x00 ... 0xFF,  break at Oracle = true,
//        ==> fix IV[i] value that after decoding will lead to the new padding value (0x0C), let´s call it DByte
//        Cipher[i] ^ DByte = new_pad  => Cipher[i] ^ DByte = 0x0C
//                                        Plain[i] = Cipher[i] ^ IV[i] = (Cipher[i] ^ DByte) ^ (DByte ^ IV[i])  = 
//                                                                   = 0x0C ^ (DByte ^ IV[i]) 
// 4) repeat for all pads 0x0D ... block_size 

// 
// CIPHER2:     C21 C22 C23 C24 C25 C26 C27     CIPHER1: C11 C12 C13 C14 C15 C16 C17
// INTERM2:     I21 I22 I23 I24 I25 I26 I27     INTERM1: I11 I12 I13 I14 I15 I16 I17
// XOR CIPHER1: C11 C12 C13 C14 C15 C16 C17     XOR IV:  IV1 IV2 IV3 IV4 IV5 IV6 IV7
// PLAIN2:       XX  XX  XX  OB  OB  OB  OB     PLAIN1:   XX  XX  XX  XX  XX  XX  XX
//
// PLAIN2 XOR INTERM2 = CIPHER1                 PLAIN1 XOR INTERM1 = IV
// => INTERM2 = CIPHER1 XOR PLAIN2              => INTERM1 = IV XOR PLAIN1
// =>  PLAIN2 = CIPHER1 XOR INTERM2             =>  PLAIN1 = IV XOR INTERM1

// Using IV = C1, to decrypt C2



//  int IV_index=1; // From now altering padding in C2 directly
//  IV_index = 0;
//  pad = 0;
ret = alg_find_plaintext_byte_by_padding_forge(0,ctext,BLOCK_SIZE,1);
if (ret == -1) goto err;

err:
  printf("\n");

  Oracle_Disconnect();
}
