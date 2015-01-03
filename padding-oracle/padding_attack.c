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
  unsigned char interm[48/block_size][block_size] = {0};
  unsigned char  plain[48/block_size][block_size] = {0};

int main(int argc, char *argv[]) {
  unsigned char ctext[48]; // allocate space for 48 bytes, i.e., 3 blocks
  int i, tmp, ret;
  FILE *fpIn;

  if (argc != 2) {
    printf("Usage: %s <filename>\n",argv[0]);
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
  int not_padded_bytes_pos = 0;

  // STEP 1
  // Looking for padding length
  // Will change IV to find misformated PKCS#5 string
  //
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
          not_padded_bytes_pos = i;
          break;
      }
    }
  }

  int pad = block_size - not_padded_bytes_pos;
  printf("\nPadded size = %d\n", pad);
  printf("The padding is: ");
  for (i=0; i<block_size; i++)
  {
       if (i < not_padded_bytes_pos) printf ("XX ");
       else printf("%.2X ", pad);
  }

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

int new_pad=pad;
while (new_pad < block_size)
{
  new_pad++;

  for (i = block_size; i > not_padded_bytes_pos; i++) 
  {
    cipher[IV_index][i] ^= pad ^ new_pad;
  }

  for (i = 0; i < 0xFF; i++)
  {
    cipher[IV_index][block_size - new_pad] = i;
    printf("\nnew padded size = %d", new_pad);
    printf("\nnew IV is: ");
    for (j=0; j<block_size; j++)
    {
          printf("%.2X ", cipher[IV_index][i]);
    }
    ret = Oracle_Send((unsigned char*)cipher, 3);
    if (ret == 1) break;
  }

  if (ret == 0)
  {
     printf("Padding oracle attack failed!\n");
     return -1;
  }

  plain[0][block_size - new_pad] = new_pad ^ ( i ^ cipher[IV_index][block_size - new_pad]);
  printf("\nplain0 is: ");
  for (j=0; j<block_size; j++)
  {
          printf("%.2X ", plain[0][i]);
  }
}
#if 0

// CBC DECRYPTION SCHEME
// INTERMEDIARY_BLOCK = DECRYPTED RECIEVED BLOCK WITH SYNCHRONOUS CRYPTOGRAPHIC KEY
//
// PLAINTEXT_1  =            IV  XOR  INTERMEDIARY_BLOCK_1
// PLAINTEXT_2  =  CIPHER_BLOCK1 XOR  INTERMEDIARY_BLOCK_2
// PLAINTEXT_3  =  CIPHER_BLOCK2 XOR  INTERMEDIARY_BLOCK_3

//..... STEP 2
// If [Intermediary Byte] ^ 0x3C == 0×0B,
// then [Intermediary Byte] == 0x3C ^ 0×0B,
// so [Intermediary Byte] == 0x37
//.....
for (block_count = 0; block_count < (48/block_size); block_count++) // block number
for (i = block_size; i > not_padded_bytes_pos; i++)                 // byte of padding within block
{
  interm[block_count][i] = pad ^ cipher[block_count][i];
}

//..... STEP 3
// Once you know the intermediary byte value, 
// we can deduce what the actual decrypted value
// is. Just XOR it with the previous cipher text.
// Look at the CBC mode decryption figure.
//.....

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
#endif

  printf("\n");

  Oracle_Disconnect();
}
