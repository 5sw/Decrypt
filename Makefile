all: Decrypt Encrypt	

Decrypt: Decrypt.o Buffer.o
	clang -o $@ $^

Encrypt: Encrypt.o Buffer.o
	clang -o $@ $^

Decrypt.o: Decrypt.c Buffer.h Common.h
Buffer.o: Buffer.c Buffer.h
Encrypt.o: Encrypt.c Buffer.h Common.h

.c.o:
	clang -c -o $@ $<

