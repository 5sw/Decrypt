all: Decrypt

Decrypt: Decrypt.o Buffer.o
	clang -o $@ Decrypt.o Buffer.o

Decrypt.o: Decrypt.c Buffer.h Common.h
Buffer.o: Buffer.c Buffer.h

.c.o:
	clang -c -o $@ $<

