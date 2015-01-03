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

  #define block_size (16)
  unsigned char cipher[48/block_size][block_size] = {0};
  unsigned char interm[48/block_size][block_size] = {0};
  unsigned char  plain[48/block_size][block_size] = {0};

int main(int argc, char *argv[]) {
  unsigned char ctext[48]; // allocate space for 48 bytes, i.e., 3 blocks
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

  for(i=0; i<48; i++) {
    fscanf(fpIn, "%02x", &tmp);
    ctext[i] = tmp;
  }

  fclose(fpIn);

  int j = -1;
  int k = -1;

  for (i=0; i< 48; i++)
  {
    
    if (i%block_size == 0) 
    {
	     printf("\nc%d: ",++j);
    }

    cipher[j][i%block_size]=ctext[i];
    printf("%.2X ",((unsigned char*)cipher)[i]);
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
  printf("\nConsider block #%d has padding\n", IV_index+1);
  for (i=0; i<block_size; i++)
  {
    cipher[IV_index][i]++; 
    ret = Oracle_Send((unsigned char*)cipher, 3); // the first argument is an unsigned char array ctext;
                                 // the second argument indicates how many blocks ctext has
    if ((ret==0) && (i==0))
    {
        printf("All message padded?\n");
        break;
    } else {
      if (verbose) printf("Changed %d-th element in IV, oracle returned: %d\n", i, ret);
      if (ret==0) {
          not_padded_bytes_pos = i;
          break;
      }
    }
  }
  if (not_padded_bytes_pos == 0) printf("\nBlock #%d has no PKCS#5 padding\n", IV_index+1);
} while ((not_padded_bytes_pos == 0) && (++IV_index < (48/block_size - 1)));

Oracle_Disconnect();

  int pad = block_size - not_padded_bytes_pos;
  printf("\nPadded size = %d\n", pad);
  printf("The padding is: ");
  for (i=0; i<block_size; i++)
  {
       if (i < not_padded_bytes_pos) printf ("XX ");
       else printf("%.2X ", pad);
  }

printf("\n");

  //restore IV to correct initial value
  for (i = 0; i <= not_padded_bytes_pos; i++) cipher[IV_index][i] = cipher[IV_index][i]-1;

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


for (j = 0; j <= pad; j++)
        plain[IV_index][block_size - j] = pad ^ ( cipher[IV_index][block_size - j] ^ cipher[IV_index-1][block_size - j]);
IV_index++; // From now altering padding in C2 directly
Oracle_Connect();

int new_pad=pad;
while (new_pad < block_size)
{
  new_pad++;
  printf("\n\n  padding: ");
  for (i = 0; i < block_size; i++)
  {
       if (i < block_size - new_pad) printf ("XX ");
       else printf("%.2X ", new_pad);
  }

   
  for (i = 0; i <= pad; i++) 
  {
    cipher[IV_index][block_size - i] ^= pad ^ new_pad;
    // 9F  =  9E ^ 0x06 ^ 0x07
  }

  for (i = 0; i <= 0xFF; i++)
  {
    cipher[IV_index][block_size - new_pad] = i;
    if (verbose)
    {
    	printf("\nnew IV is: ");
    	for (j=0; j<block_size; j++)
    	{
          printf("%.2X ", cipher[IV_index][j]);
    	}
    }

    ret = Oracle_Send((unsigned char*)cipher, 3);
    if (verbose) printf(", ret = %d", ret);
    if (ret == 1) break;
  }

  if (ret == 0)
  {
     printf("\nPadding oracle attack failed!\n");
     return -1;
  }
  	plain[IV_index-1][block_size - new_pad] = new_pad ^ ( i ^ cipher[IV_index-1][block_size - new_pad]);

  printf("\ntext %d is: ", IV_index);
  for (j=0; j<block_size; j++)
  {
          printf("%.2X ", plain[IV_index-1][j]);
  }

  for (j=0; j<block_size; j++)
  {
          if (isprint(plain[IV_index-1][j]))
		printf("%c", plain[IV_index-1][j]);
	  else  printf(".");
  }
}
  printf("\n");

  Oracle_Disconnect();
}
