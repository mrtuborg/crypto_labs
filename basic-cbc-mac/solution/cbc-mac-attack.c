#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LENGTH 512
#define BLOCK_SIZE 16
unsigned char m1_second[16]="I, the server, h";
unsigned char m2_second[16]="ereby agree that";
unsigned char m3_second[16]=" I will pay $100";
unsigned char m4_second[16]=" to this student"; // m4_second
unsigned char m1_first[16]; // = TAG0 ^ m3_second
unsigned char m2_first[16]; // = m4_second


int main(int argc, char *argv[]) {
    unsigned char message[MAX_LENGTH];
    unsigned char tag[BLOCK_SIZE], tag_first[BLOCK_SIZE];
    int i, mlength, ret;
    FILE *fpIn;

    if (argc != 2) {
        printf("Usage: sample <filename>\n");
        return -1;
    }

    fpIn = fopen(argv[1], "r");
    for(i=0; i<MAX_LENGTH; i++) {
      if (fscanf(fpIn, "%c", &message[i]) == EOF) break;
    }
    fclose(fpIn);

    mlength = i;

    Oracle_Connect();

    // send message (of length mlength) to the Mac oracle to obtain tag
    Mac(message, mlength, tag);
    // To a forge tag we need obtain tag on modified message:
    // m0 || mm0 ^ t || mm1 ^ t || mm2 ^ t || mm3 ^ t
 
    // send message (of length mlength) and tag to be verified
    ret = Vrfy(message, mlength, tag);
    if (ret) {
        printf("\nMessage 0 verified successfully!\n");
    } else {
        printf("\nMessage 0 verficiation failed.\n");
    }
    
    printf("\nm1: ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", message[i]);
    printf("\nm2: ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", message[i+16]);
    printf("\nT = ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", tag[i]);

    for (int i=0; i<BLOCK_SIZE; i++)
    {
    	m1_first[i]=m3_second[i] ^ tag[i];

    }

    for (int i=0; i<BLOCK_SIZE; i++)
    {
    	m2_first[i]=m4_second[i];
    }
	printf("\n");
	
	unsigned char m_first[32];
	memcpy(m_first+00, m1_first, 16);
	memcpy(m_first+16, m2_first, 16);
	
	printf("\nm'1:   ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", m_first[i]);
    printf("\nm'2:   ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", m_first[i+16]);
	
	Mac(m_first, 32, tag_first);
    printf("\nT' = ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", tag_first[i]);
	printf("\n");
	
	ret = Vrfy(m_first, 32, tag_first);
    if (ret) {
        printf("\nMessage 1 verified successfully!\n");
    } else {
        printf("\nMessage 1 verficiation failed.\n");
    }
    
	unsigned char m_second[64];
	memcpy(m_second+00, m1_second, 16);
	memcpy(m_second+16, m2_second, 16);
	memcpy(m_second+32, m3_second, 16);
	memcpy(m_second+48, m4_second, 16);
	
	printf("\nm''1:   ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", m_second[i]);
    printf("\nm''2:   ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", m_second[i+16]);
	printf("\nm''3:   ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", m_second[i+32]);
    printf("\nm''4:   ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", m_second[i+48]);
    printf("\nT' = ");
    for (int i=0; i<BLOCK_SIZE; i++)
	printf("%.2X ", tag_first[i]);
	printf("\n");
	
	Mac(m_second, 64, tag_first);
	ret = Vrfy(m_second, 64, tag_first);
    if (ret) {
        printf("\nMessage 2 verified successfully!\n");
    } else {
        printf("\nMessage 2 verficiation failed.\n");
    }
    

	
    Oracle_Disconnect();
}
