cbc-mac-attack: cbc-mac-attack.o oracle.o
	gcc -std=c99  -o $@ cbc-mac-attack.o oracle.o

vrfy:   vrfy.o cbcmac.o aes_core.o
	gcc -0 vrfy vrfy.o cbcmac.o aes_core.o -lpthread

mac:    mac.o cbcmac.o aes_core.o
	gcc -o mac mac.o cbcmac.o aes_core.o -lpthread

vrfy.o: vrfy.c cbcmac.h
	gcc -c vrfy.c

mac.o:  mac.c cbcmac.h
	gcc -c mac.c

cbcmac.o: cbcmac.c cbcmac.h
	gcc -c cbcmac.c

aes_core.o: aes_core.c
	gcc -c aes_core.c

cbc-mac-attack.o: cbc-mac-attack.c oracle.h
	gcc -std=c99 -c -g cbc-mac-attack.c

oracle.o: oracle.c oracle.h
	gcc -c oracle.c
