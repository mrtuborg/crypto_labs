#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <signal.h> 

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
  #define CTEXT_LENGTH (48)
  #define BLOCKS_COUNT (CTEXT_LENGTH/BLOCK_SIZE)

  unsigned char _cipher[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char cipher[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char interm[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char  plain[BLOCKS_COUNT][BLOCK_SIZE] = {0};

int main(int argc, char *argv[]) {
  unsigned char ctext[CTEXT_LENGTH]; // allocate space for 48 bytes, i.e., 3 blocks
  int i, tmp, ret;
  FILE *fpIn;
  int verbose = 0;
 // Register signals 
  signal(SIGINT, keybreak); 
  if (argc < 2) {
    printf("Usage: %s <filename>\n",argv[0]);
    return -1;
  }
  
  if ( argc>2 && (!strcmp(argv[2],"-v"))) verbose = 1;

  fpIn = fopen(argv[1], "r");

  for(i=0; i<CTEXT_LENGTH; i++) {
    fscanf(fpIn, "%02x", &tmp);
    ctext[i] = tmp;
  }

  fclose(fpIn);

  int j = -1;
  int k = -1;

  for (i=0, j=-1; i< CTEXT_LENGTH; i++)
  {
    
    if (i%BLOCK_SIZE == 0) 
    {
	     printf("\nc%d: ",++j);
    }

    _cipher[j][i%BLOCK_SIZE]=ctext[i];
    cipher[j][i%BLOCK_SIZE]=ctext[i];
    printf("%.2X ",((unsigned char*)_cipher)[i]);
  } 
  printf("\n");

  Oracle_Connect();
  int IV_index = 0;
  int not_padded_bytes_pos = 0;

  // STEP 1
  // Looking for padding length
  // Will change IV to find misformated PKCS#5 string
  //
do    // Trying each cipher block as IV vector for the next block
{
  printf("\nConsider block C%d has padding\n", IV_index+1);
  for (i=0; i<BLOCK_SIZE; i++)
  {
    cipher[IV_index][i] = _cipher[IV_index][i] + 1; 
    ret = Oracle_Send((unsigned char*)cipher[IV_index], 2); // the first argument is an unsigned char array ctext;
                                 // the second argument indicates how many blocks ctext has
    if ((ret==0) && (i==0))
    {
        printf("All message padded?\n");
        break;
    } else {
      if (verbose) printf("Changed %d-th element in C%d, oracle returned: %d\n", i, IV_index, ret);
      if (ret==0) {
          not_padded_bytes_pos = i;
          break;
      }
    }
  }
  if (not_padded_bytes_pos == 0) printf("\nBlock C%d has no padding\n", IV_index+1);
} while ((not_padded_bytes_pos == 0) && (++IV_index < (BLOCKS_COUNT - 1)));

Oracle_Disconnect();

int pad = BLOCK_SIZE - not_padded_bytes_pos;
printf("\nBlock C%d has padding size = %d", IV_index+1, pad);
printf("\n   padding: ");
for (i=0; i<BLOCK_SIZE; i++)
{
     if (i < not_padded_bytes_pos) printf ("XX ");
     else printf("%.2X ", pad);
}

printf("\n");

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
//IV_index=1; // From now altering padding in C2 directly
IV_index = 0;
pad = 0;

for (j = 1; j <= pad; j++)
{
        interm[IV_index][BLOCK_SIZE - j] = pad ^ _cipher[IV_index-1][BLOCK_SIZE - j];
         plain[IV_index][BLOCK_SIZE - j] = pad;
}


Oracle_Connect();

int new_pad=pad;
unsigned char DByte = 0;

while (new_pad < BLOCK_SIZE)
{
  //if (new_pad > pad) cipher[IV_index][BLOCK_SIZE - new_pad] = DByte ^ (new_pad) ^ (new_pad+1);
  //else cipher[IV_index][BLOCK_SIZE - new_pad] = _cipher[IV_index][BLOCK_SIZE - new_pad] ^ pad ^ new_pad+1;

  new_pad++;
  for (i = 1; i <= pad; i++) // i: [1..11], BLOCK_SIZE-i: [15...5]
  {
    cipher[IV_index][BLOCK_SIZE - i] = _cipher[IV_index][BLOCK_SIZE - i] ^ pad ^ new_pad;
    // Katz: 9F  =  9E   ^ 0x06    ^   0x07
    //                    old pad     new pad
  }
  
  for (i = pad+1; i < new_pad; i++)
    cipher[IV_index][BLOCK_SIZE - i] ^= (new_pad-1) ^(new_pad);

  for (i = new_pad; i <= BLOCK_SIZE; i++) // i: [13..16], BLOCK_SIZE-i: [3...0]
  {
    cipher[IV_index][BLOCK_SIZE - i] = _cipher[IV_index][BLOCK_SIZE - i];
    // Katz: 9F  =  9E   ^ 0x06    ^   0x07
    //                    old pad     new pad
  }

 
  printf("\n\nC%d padding: ", IV_index+1);
  for (i = 0; i < BLOCK_SIZE; i++)
  {
       if (i < BLOCK_SIZE - new_pad) printf ("XX ");
       else printf("%.2X ", new_pad);
  }


  for (i = 0; i <= 0xFF; i++) // guess loop
  {
    cipher[IV_index][BLOCK_SIZE - new_pad] = i; // BLOCK_SIZE-new_pad: 16 - 12: 4
    if (verbose)
    {
    	printf("\n new C%d is: ", IV_index);
    	for (j=0; j<BLOCK_SIZE; j++)
    	{
          printf("%.2X ", cipher[IV_index][j]);
    	}
    }

    ret = Oracle_Send((unsigned char*)cipher[IV_index], 2);
    if (verbose) printf(", ret = %d", ret);
    if (ret == 1) 
    {
      DByte = i;
      break;
    }
  }

  if (ret == 0)
  {
     printf("\nPadding oracle attack failed!\n");
     goto err;
  }
 
  // I2 = C1´ ^  P2´
  	interm[IV_index+1][BLOCK_SIZE - new_pad] = DByte ^ new_pad;
  // P2 = C1 ^ I2
     plain[IV_index+1][BLOCK_SIZE - new_pad] = _cipher[IV_index][BLOCK_SIZE - new_pad] ^ interm[IV_index+1][BLOCK_SIZE - new_pad];

  printf("\nplain %d is: ", IV_index+1);
  for (j=0; j<BLOCK_SIZE; j++)
  {
          printf("%.2X ", plain[IV_index+1][j]);
  }

  for (j=0; j<BLOCK_SIZE; j++)
  {
          if (isprint(plain[IV_index+1][j]))
		printf("%c", plain[IV_index+1][j]);
	  else  printf(".");
  }
}

err:
  printf("\n");

  Oracle_Disconnect();
}
