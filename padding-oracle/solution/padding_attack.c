#include <oracle.h>
#include <unistd.h>
#include <assert.h>

#include <globals.h>
#include <data.h>
#include <ui.h>


// Read a ciphertext from a file, send it to the server, and get back a result.
// If you run this using the challenge ciphertext (which was generated correctly),
// you should get back a 1. If you modify bytes of the challenge ciphertext, you
// may get a different result...

// Note that this code assumes a 3-block ciphertext.

  //#define CTEXT_LENGTH (48)
  //#define BLOCKS_COUNT (CTEXT_LENGTH/BLOCK_SIZE)

 /* unsigned char cipher[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char _cipher[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char interm[BLOCKS_COUNT][BLOCK_SIZE] = {0};
  unsigned char  plain[BLOCKS_COUNT][BLOCK_SIZE] = {0};
*/




unsigned char alg_find_CBC_padding_value(const unsigned char *original_ctext,
                                         const unsigned int   block_size,
                                         const unsigned int   blocks_count)
{
       int ret                      = 0;    // Oracle responces
  unsigned int             IV_index = 0;    // Will iterate from 0,1... until found padded message
  unsigned int not_padded_bytes_pos = 0;

  unsigned char* ctext = malloc(block_size*blocks_count);
  memcpy (ctext, original_ctext, block_size*blocks_count);
  
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
        DEBUG("Changed %d-th element in C%d, oracle returned: %d\n", i, IV_index, ret);
        if (ret == 0) {
            not_padded_bytes_pos = i;
            break;
        }
      }
    }
    if (not_padded_bytes_pos == 0) printf("\nBlock C%d has no padding\n", IV_index+1);
  } while ((not_padded_bytes_pos == 0) && (++IV_index < (blocks_count - 1)));
  
  Oracle_Disconnect();
  free(ctext);
  return block_size - not_padded_bytes_pos;
}



int alg_padding_forgery(      unsigned char  new_pad,
                              unsigned char *ctext,
                        const unsigned int   block_size)
{
  int DByte = -1;
  int ret   =  0;

  Oracle_Connect();
  for (int i = 0; i <= 0xFF; i++) // guess loop
  {
    ctext[block_size - new_pad] = i; // BLOCK_SIZE-new_pad: 16 - 12: 4
	VERBOSE(print_hex_vector(ctext, block_size),"\n new C is: ");
	
    ret = Oracle_Send((unsigned char*)ctext, 2);
    DEBUG(", ret = %d", ret);
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



int alg_intermvector(		 unsigned char   pad,
					   const unsigned char*  original_ctext,
							 unsigned char*  interm,
					   const unsigned int    block_size)
{
  unsigned char DByte = 0;

  unsigned char* ctext = malloc(2*block_size);
  memcpy (ctext, original_ctext, 2*block_size);
  while (pad < BLOCK_SIZE)
  {
	
    pad++;
    //Loop at the end of the block: pad - already correctly guessed value at the previous iteration
    for (int i = 1; i < pad; i++) // i: [1..11], BLOCK_SIZE-i: [15...5]
    {
      ctext[block_size - i] = ctext[block_size - i] ^ (pad - 1) ^ pad;
      // Katz: 9F  =  9E   ^ 0x06    ^   0x07
      //                    old pad     new pad
    }
    
    // New element to guess:
    //for (int i = pad+1; i < new_pad; i++)
    //  ctext[block_size - pad + 1] ^= (new_pad-1) ^(new_pad);

    //for (int i = new_pad; i <= BLOCK_SIZE; i++) // i: [13..16], BLOCK_SIZE-i: [3...0]
    //{
    //  ctext[block_size - i] = ctext[block_size - i];
      // Katz: 9F  =  9E   ^ 0x06    ^   0x07
      //                    old pad     new pad
    //}

	// Forging C[IV_index] block will affect on m[IV_index + 1] message
	printf("\n\npad sample: ");
    print_pad_sample(pad, block_size);

    int forgery_result = alg_padding_forgery(pad, ctext, block_size);
    if (forgery_result == -1) { free(ctext); return -1; }
    else DByte = forgery_result;
   

    // I2 = C1´ ^  P2´
    // Possition to calculate intermediate vector: block_size - new_pad
    // for new forged padding: X1 X2 X3 05 05 05 05 05, we can calculate X3 byte: 8 - 5 = 3
    
    interm[block_size - pad] = DByte ^ pad;
    printf("\n   I3[%d] = P'3 ^ C'2 :  0x%.2X =  0x%.2X ^ 0x%.2X", block_size-pad, interm[block_size - pad], pad, DByte);

    printf("\nintermediate vector: ");
    print_2ndpart(block_size - pad, block_size, interm);

  }

  free(ctext);
  return 0;
}

int alg_plain_recovery( const unsigned char* interm,
						const unsigned char* cipher,
						const unsigned int block_size,
						unsigned char* plain)
{
	for (int i=0; i<block_size; i++)
		plain[i] = interm[i] ^ cipher[i];
	
	return 0;
}

int main(int argc, char *argv[]) {
  unsigned long  ctext_length;
  unsigned char *ctext;
 
  
  if (get_lineopts(argc, argv) == -1) return -1;
  if (load_file(argv[1], &ctext, &ctext_length) == -1) return -1;
  DEBUG("DEBUG mode: verbose turned on\n");
  
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
  printf("\n\nC%d padding: ", IV_index);
print_pad_sample(pad, BLOCK_SIZE);

	  printf("\nChallenge is:\n");
  dbldim_array_print(ctext, 0, 1, BLOCK_SIZE);
  dbldim_array_print(ctext, 1, 1, BLOCK_SIZE);
  dbldim_array_print(ctext, 2, 1, BLOCK_SIZE);
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
	unsigned char* interm = malloc (BLOCK_SIZE);
	unsigned char* plain = malloc (BLOCK_SIZE*2);
	
	for (int i=1; i>=0; i--)
	{
		ret = alg_intermvector(pad,&ctext[i*BLOCK_SIZE],interm, BLOCK_SIZE); // I3=P3' ^ C(C2´)
		if (ret == -1) goto err;
		
			printf("\nChallenge is:\n");
		dbldim_array_print(ctext, 0, 1, BLOCK_SIZE);
		dbldim_array_print(ctext, 1, 1, BLOCK_SIZE);
		dbldim_array_print(ctext, 2, 1, BLOCK_SIZE);
		
		DEBUG("Plain %d: \n", i);

		alg_plain_recovery(interm, &ctext[i*BLOCK_SIZE], BLOCK_SIZE, &plain[i*BLOCK_SIZE]); // P3 = I3 ^ C2
		printf("\n");
		pad = 0;
	}
	
	for (int i=0; i<2; i++)
	{
		printf("\n Plain %d: ",i);
		print_hex_vector(&plain[i*BLOCK_SIZE], BLOCK_SIZE);
		print_char_vector(&plain[i*BLOCK_SIZE], BLOCK_SIZE);
	}
err:
	printf("\n");
	free(plain);
	free(interm);
	
	return 0;
}
