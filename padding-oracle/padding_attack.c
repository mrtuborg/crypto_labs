#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Read a ciphertext from a file, send it to the server, and get back a result.
// If you run this using the challenge ciphertext (which was generated correctly),
// you should get back a 1. If you modify bytes of the challenge ciphertext, you
// may get a different result...

// Note that this code assumes a 3-block ciphertext.

  #define block_size (16)
  unsigned char cipher[48/block_size][block_size] = {0};
  unsigned char plain[48/block_size-1][block_size] = {0};

int main(int argc, char *argv[]) {
  unsigned char ctext[48]; // allocate space for 48 bytes, i.e., 3 blocks
  int i, tmp, ret;
  FILE *fpIn;

  if (argc != 2) {
    printf("Usage: sample <filename>\n");
    return -1;
  }

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
  int IV_index = 1;
  int padded = 0;
  // find padding length
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
      printf("Changed %d-th element in IV, oracle returned: %d\n", i, ret);
      if (ret==0) {
          padded = i;
          break;
      }
    }
  }

  printf("\nPadded size = %d\n", block_size - padded);
  printf("The padding is: ");
  for (i=0; i<block_size; i++)
  {
       if (i < padded) printf ("XX ");
       else printf("%.2X ", block_size - padded);
  }

  //restore IV
  for (i=0; i<=padded; i++) cipher[IV_index][i] = cipher[IV_index][i]-1;


  int new_pad=0;
  for (new_pad=block_size-padded+1; new_pad<=block_size; new_pad++)
  {
    printf("\nSet new padding to %.2X:\n", new_pad);

    for (i=block_size-1; i>=block_size-new_pad; i--)
    {
      //printf("%.2X: %.2X^%.2X^%.2X=",i,cipher[IV_index][i], (block_size - padded), new_pad);
        cipher[IV_index][i]^= (block_size - padded)^(new_pad);
      //  printf("%.2X\n",cipher[IV_index][i]);

    }

    printf("IV: ");
    for (i=0; i<block_size; i++) printf("%.2X ", cipher[IV_index][i]);

    printf("\nGuess the %d-th byte of IV with new padding:\n", block_size-new_pad+1);
    for (i=0; i<=0xFF; i++)
    {

        k=-1;
        cipher[IV_index][block_size-new_pad]=i;
#if 0 
        for (j=0; j< 48; j++)
        {
    
            if (j%block_size == 0) printf("\nc%d: ",++k);
            printf("%.2X ",((unsigned char*)cipher)[j]);
        } 
      printf("\n");
#endif

      //sleep(1);
      ret = Oracle_Send((unsigned char*)cipher, 3);
     //printf("ret=%d\n",ret);
      if (ret == 1)
      {
        printf("ret=%d\n",ret);
        cipher[IV_index][block_size-new_pad]= i ^ cipher[IV_index][block_size-new_pad];
        break;
      }
    }

    while (k<2)
    for (j=0; j< 48; j++)
    {
    
            if (j%block_size == 0) printf("\nc%d: ",++k);
            printf("%.2X ",((unsigned char*)cipher)[j]);
    } 
      printf("\n");

    if (ret == 0) break;
    printf("plain_text:\n");
    for (j=0; j<48/block_size-1; j++)
    { 
      printf("\nstring %d: ",j); 
      for (i=0; i<block_size; i++) printf("%.2X ", plain[j][i]);
    }


      

  }


  printf("\n");

  Oracle_Disconnect();
}
