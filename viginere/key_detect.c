#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>


#define INPUT_FILE "ciphertext2"

double lang_freq_table[26] = 
{ 8.167, //a
  1.492, //b
  2.782, //c
  4.253, //d
 12.702, //e
  2.228, //f
  2.015, //g
  6.094, //h
  6.966, //i
  0.153, //j
  0.772, //k
  4.025, //l
  2.406, //m
  6.749, //n
  7.507, //o
  1.929, //p
  0.095, //q
  5.987, //r
  6.327, //s
  9.056, //t
  2.758, //u
  0.978, //v
  2.360, //w
  0.150, //x
  1.974, //y
  0.074  //z
};

int calc_byte_quantity(unsigned char byte, int array_size, unsigned char* array)
{
    int i=0;
    int quantity=0;
    //printf("Count quantity of 0x%.2X in stream: ", byte);
    for (i=0; i<array_size; i++) {
    	//printf("0x%.2X ",array[i]);
        if (array[i] == byte) quantity++;
    }
    //printf(";  quantity=%d\n", quantity);
    return quantity;
}

int main()
{
	char ctext[1024]={0};
	char cdigit[3]={0};
	FILE *fpIn, *fpOut, *fpOut_freq;
	int i, j, k;
	unsigned char idigit[1024];

	int freq_digit[256] = {0};
	int freq_next_dist[1024] = {-1};
	int next_pos[1024] = {0};
	int next_pos_next = 0;

	int k_length, key_length_max = 0; 

	fpIn = fopen(INPUT_FILE, "r");
	fpOut = fopen("plaintext", "w");
	fpOut_freq = fopen ("frequencies","w");

	fscanf(fpIn, "%s", ctext); 
	// printf("%s\n\n",ctext);

	for (i=0, k=0; i < strlen(ctext); i+=2, k++)
	{
		memcpy(cdigit, ctext + i, 2);
		cdigit[2]=0;

		idigit[k] = (char)strtol(cdigit, NULL, 16);
	} 
  	int size = k;
  	unsigned char index;
	double q_distrib[256];
	unsigned char seeded_array[1024];
	double p_distrib[1024];
	double freq[1024] = {0};
	double sumsqr = 0;

	double sumsqr_max = 0;
	for (k_length = 1; k_length <= 31; k_length++) 
	{
		printf("\nk_length: %d\n", k_length);
		//printf("seeded array: \n");
		for (i=0, j=0; i<size; i+=k_length) // Take every k_length@´s byte 
		{
			seeded_array[j++] = idigit[i];
		//     printf("%.2X ", idigit[i]);
		}

		for (k=0; k<j; k++)
		{
			freq[k] = (double)calc_byte_quantity(seeded_array[k],j,seeded_array)/j;
		//    printf("\n freq for %.2X is %f",seeded_array[k], freq[k]);
		}

		printf("\nsumsqr = ");
		sumsqr = 0;
		for (i = 0; i < j; i++)
		{
			sumsqr += pow(freq[i],2);
		//	printf(" + %f (%f^2)", pow(freq[i],2), freq[i]);
		}
		printf(" = %f\n", sumsqr);

		if (sumsqr_max < sumsqr) {
			sumsqr_max = sumsqr;
			key_length_max = k_length;
		} 
	    
	}
//-------
	k_length = key_length_max;
	printf ("key length is %d \n", k_length);
	j = 0;
	double k_candidate[1024][255]={0};
	unsigned char seeded_stream[1024][1024]={0};
	unsigned char translated_stream[1024]={0};
	double freq_stream[1024]={0};
	int row_count = 0;
	for (j=0; j<k_length; j++)
	{
		row_count = 0;
		for (i=j; i<size; i+=k_length)
		{
			seeded_stream[row_count++][j] = idigit[i]; // i - row, message, j - column, letter in message. 
		}
		printf("row_count = %d\n", row_count);
	}

	
	double sumsqr_trans[1024]={0};
	unsigned char scl[1024]={0};
	int n=0, m = 0;

	double symbol_freq_in_text;

	for (j=0; j<k_length; j++) // go through the all streams (fix column)
	{
		for (k=0; k <= 0xFF; k++) // B from video
		{
			double sum_qp=0;
			k_candidate[j][k] =1; // k - candidate value, j - stream number, check bad candidates with 0, good with sum_qp
			
			for (i=0; i<row_count; i++) // go through the all lines (messages, fix row)
			{
				
		 		translated_stream[i] = seeded_stream[i][j] ^ k;
//		 	printf("seeded symbol: %.2X, \n",seeded_stream[i][j]);
//		 	for (z=0; z<row_count; z++) printf("%c",seeded_stream[][z]);
//		 	for (z=0; z<row_count; z++) printf("%c",translated_stream[z]);

		 		char symbol = translated_stream[i];

		 		if ((!isalpha(symbol)) && (!isdigit(symbol)) && (symbol!=0x20)){
		 		//if ((translated_stream[i] > 126) || (translated_stream[i] < 32)) {
		 		// Bad B-key candidate for stream m, check next message
		 			k_candidate[j][k] =0;
		 		//printf(" candidate is out of ASCII selected range\n");
		 			break; // Take next B-key
		 		} else {
		 			

			 		freq_stream[i] = (double)calc_byte_quantity(symbol,row_count,translated_stream)/(row_count);
			 		double symbol_freq_in_lang;
			 		if (symbol >= 'A' && symbol <= 'Z') symbol_freq_in_lang = lang_freq_table[symbol-'A'];
						else if (symbol >= 'a' && symbol <= 'z') symbol_freq_in_lang = lang_freq_table[symbol-'a'];
			 				else symbol_freq_in_lang = 0;

			 		//sum_qp += pow(freq_stream[i],2); //*symbol_freq_in_lang;
			 		sum_qp += freq_stream[i]*symbol_freq_in_lang;
			 	}
			}
			k_candidate[j][k] =sum_qp;


			if ((k_candidate[j][k] > 0) ) { // && (sum_qp < 0.7) && (sum_qp > 0.5)) {
				printf("B = 0x%.2X j = 0x%.2X: ",k,j);
				printf("  sum_qp = %f,  translated_stream: ",k_candidate[j][k]);
				for (i=0; i<row_count; i++) printf("%c",translated_stream[i]);
				printf("\n");
			}
	}
}
//B = 0x0C j = 0x0C:   sum_qp = 4.883286,  translated_stream: enru"<s
//B = 0x2C j = 0x0C:   sum_qp = 4.883286,  translated_stream: ENRUga
//char key[7] = {0xBA,0x1F,0x91,0xB2,0x53,0xCD,0x3E};
char key[31] = { 0xD2, 0x1A, 0x04, 0x9B, 0xD0, 0x73, 0x23, 0xC8,
				 0x39, 0x98, 0xCE, 0x09, 0x0E, 0xBC, 0x86, 0xDA,
				 0xC9, 0xE0, 0x39, 0x89, 0x2A, 0x5F, 0x72,
				 0x67, 0x83, 0xA5, 0x61, 0xFD, 0x25, 0xEE, 0x14};
for (int i=0; i<size; i++) printf("%c",idigit[i]^key[i%31]);


	fclose(fpIn);
	fclose(fpOut);
	fclose(fpOut_freq);
	return 0;
}