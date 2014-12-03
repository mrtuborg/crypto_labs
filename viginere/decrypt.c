#include <stdio.h>
#include <string.h>
#include <math.h>

int array_int_max(int size, int* array)
{
    int index = 0, max = 0;
    int i = 0;
    for (i = 0; i<size; i++) if (array[i] > max) { max = array[i]; index = i; }
    return index;
}
int calc_byte_quantity(unsigned char byte, int array_size, unsigned char* array)
{
    int i=0;
    int quantity=0;
    for (i=0; i<array_size; i++) {
        if (array[i] == byte) quantity++;
    }    
    return quantity;
}

int calc_word_quantity(unsigned int word, int array_size, int* array)
{
    int i=0;
    int quantity=0;
    for (i=0; i<array_size; i++) if (array[i] == word) quantity++;

    return quantity;
}


void build_quantity_array(int in_array_size, char* in_array, int* q_array)
{
     int v =0;
     for (v = 0; v <= 0xFF; v++)  q_array[(unsigned char)v] = calc_byte_quantity((unsigned char)v, in_array_size, in_array);
}

double sqr_summ(int size, int *q_array, int m_length)
{
    int i=0;
    double result = 0;
//    printf("r = ");
    for (i=0; i<size; i++) 
    {
	result += pow((float)q_array[i]/m_length,2);
//    	printf(" + %d^2", q_array[i]);
    }
//    printf(" = %f\n",result);
    return result;
}

double sqr_summ_bytes(int size, char *q_array, int m_length)
{
    int i=0;
    double result = 0;
//    printf("r = ");
    for (i=0; i<size; i++) 
    {
	result += pow((float)q_array[i]/m_length,2);
//    	printf(" + %d^2", q_array[i]);
    }
//    printf(" = %f\n",result);
    return result;
}

int main(void){
  char ctext[1024]={0};
  char cdigit[3]={0};
  FILE *fpIn, *fpOut, *fpOut_freq;
  int i, j, k;
  unsigned char idigit[1024];
  
  int freq_digit[256] = {0};
  int freq_next_dist[1024] = {-1};
  int next_pos[1024] = {0};
  int next_pos_next = 0;

  fpIn = fopen("ciphertext", "r");
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
  build_quantity_array(size, idigit, freq_digit);
  for (i=0; i < size; i++)
   {
	for (j=i+1; j<size; j++) 
	{
		if (freq_digit[idigit[i]] == freq_digit[idigit[j]]) 
		{
			freq_next_dist[i]=j-i;
  			printf("freq_digit[%.2X]=%d, i=%d, j=%d, freq_next_dist=%d\n",idigit[i],freq_digit[idigit[i]],i,j,freq_next_dist[i]);
			break;
		}
	}
   }

   unsigned char index;
   int next_dist_quantity[1024];
   for (i=0; i < size; i++)
   {
	index = idigit[i];
	
	fprintf(fpOut,"%d.%.2X ->",i,index);
	if (freq_digit[index] > 0)
	{	
		fprintf(fpOut,"%d, %f,",freq_digit[index], (float)(freq_digit[index])/size);
        	fprintf(fpOut," next = %d, ",freq_next_dist[i]);
		next_dist_quantity[freq_next_dist[i]]= calc_word_quantity(freq_next_dist[i], size, freq_next_dist);
		fprintf(fpOut," next quantity = %d, %f\n", next_dist_quantity[freq_next_dist[i]], (float)(next_dist_quantity[freq_next_dist[i]])/size);
	} else {
		fprintf(fpOut, "0\n");
	}
  
   }

   int next_dist_max = array_int_max(size, next_dist_quantity);
   printf("next quantity max = %d ", next_dist_quantity[next_dist_max]);
   printf("freq = %d \n", freq_digit[next_dist_max]);
   printf("\n");
   
  int k_length = 0; 
  double q_distrib[256];
  unsigned char seeded_array[1024];
  double p_distrib[1024];
  double freq[1024] = {0};
  double sumsqr = 0;

  for (k_length = 1; k_length <= 13; k_length++) 
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
        
  }

  k_length = 7;
  j = 0;

  unsigned char seeded_stream[1024][1024]={0};
  unsigned char invalid[1024]={0};
  unsigned char translated_stream[1024][1024]={0};
  for (j=0; j<k_length; j++)
  {
  	for (i=j; i<size; i+=k_length)
  	{
       		seeded_stream[i][j] = idigit[i];
	}
	
  }

double sumsqr_trans[1024]={0};
unsigned char scl[1024]={0};
int n=0, m = 0;
for (k=0; k <= 0xFF; k++)
{	
  for (j=0; j<k_length; j++)
  {
	invalid[j] =0;

  	for (i=j, m=0; i<size; i+=k_length, m++)
	{
		 translated_stream[m][j] = seeded_stream[i][j] ^ k;
		 if ((translated_stream[m][j] > 126) || (translated_stream[m][j] < 32)) invalid[j] = 1; 
	}
	if (invalid[j] == 1) continue;

	// small capital letters is between 97,122
	sumsqr_trans[j] = 0;
        for (i=0,n=0; i<m; i++)
	{	
		if ((translated_stream[i][j] < 97) || ( translated_stream[i][j] > 122)) continue;
		scl[n]=translated_stream[i][j];
		freq[n]=(double)calc_byte_quantity(scl[n],m,translated_stream[j])/m;
		sumsqr_trans[j]+=pow(freq[n],2);
		n++;
	}
  } 
}
 
char out_string[1024]={0};
for (i=0; i<k_length; i++)
{
    if (invalid[i] == 1) continue;
    printf("i=%d, sumsqr_trans=%f\n",i,sumsqr_trans[i]);
} 
  for (i=0; i<size; i++)
  {
       index = idigit[i];
       fprintf(fpOut_freq, "%.2X ", freq_digit[index]);
  }

  fclose(fpIn);
  fclose(fpOut);
  fclose(fpOut_freq);
  return 0;
} 
