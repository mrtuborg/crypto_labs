LD=gcc
CFLAGS=-std=c99 -I.
LDFLAGS=-lc

padding_attack: padding_attack.o oracle.o globals.o ui.o data.o
		 $(LD) $(LDFLAGS) -o $@ $^

%.c: padding_attack.c oracle.c globals.c ui.c data.c

.PHONY: clean
clean:
		rm padding_attack *.o


