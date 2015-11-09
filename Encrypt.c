#include "Buffer.h"
#include "Common.h"

#include <stdio.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CoreFoundation/CoreFoundation.h>

int main( int argc, const char *argv[] ) 
{
	if (argc != 3) {
		fprintf( stderr, "Call %s <input> <output>\n", argv[0] );
		return 1;
	}
  
  struct buffer inputFile = { 0 };
  if (!OpenFile(&inputFile, argv[1])) {
    fprintf(stderr, "Cannot open input file %s\n", argv[1]);
    return 1;
  }
  
  struct header header = { 0 };
  
  memcpy(header.magic, "CFG1", sizeof header.magic);
  strcpy(header.etl, "000000");
  
  CC_MD5_CTX context;
  CC_MD5_Init(&context);
  
  // Hash input data.
	CC_MD5_Update(&context,inputFile.start, inputFile.length);
  
  // Add PKCS7 padding data to hash. Decoder calculates hash over padded data.
  uint8_t pad = kCCBlockSizeAES128 - (inputFile.length % kCCBlockSizeAES128);
  for (uint8_t i = 0; i < pad; i++) {
    CC_MD5_Update(&context,&pad, sizeof pad);
  }
  
  // Finalize hash and store in header.
  CC_MD5_Final(header.plaintext_md5, &context);
    
  size_t encryptedBufferSize = inputFile.length + kCCBlockSizeAES128;
  void *encryptedBuffer = malloc(encryptedBufferSize);
  if (!encryptedBuffer) {
    fprintf(stderr, "Not enough memory to encrypt file\n");
    return 1;
  }
  size_t encryptedDataLength = 0;
  
  CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding|kCCOptionECBMode, 
    aes_key, sizeof aes_key, 
    NULL, 
    inputFile.start, inputFile.length, 
    encryptedBuffer, encryptedBufferSize, &encryptedDataLength);
  
  if (status != kCCSuccess) {
    fprintf(stderr, "Error encrypting (%d)\n", status);
    return 1;
  }
  
  header.payload_size = encryptedDataLength;
  header.padding_len = encryptedDataLength - inputFile.length;
  
  uint8_t headerData[HeaderSize] = {0};
  struct buffer headerBuf = {0};
  OpenBuffer(&headerBuf, headerData, sizeof headerData);
  
  Write(&headerBuf, header.magic, sizeof header.magic);
  Write32(&headerBuf, header.payload_size);
  headerBuf.next += sizeof header.header_md5; // Skip header_md5
  Write(&headerBuf, header.etl, sizeof header.etl);
  Write(&headerBuf, &header.unused1, sizeof header.unused1);
  Write16(&headerBuf, header.password_len);
  Write16(&headerBuf, header.padding_len);
  Write(&headerBuf, header.unused2, sizeof header.unused2);
  Write(&headerBuf, header.plaintext_md5, sizeof header.plaintext_md5);
  
  uint8_t header_md5[CC_MD5_DIGEST_LENGTH];
  CC_MD5(headerData, sizeof headerData, header_md5);
  memcpy(&headerData[8], header_md5, sizeof header.header_md5);
  
	int fdout = open( argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600 );
	if (fdout < 0) {
		fprintf( stderr, "Error: cannot write output file\n" );
		return 1;
	}
  
  bool written = write(fdout, headerData, sizeof headerData) == sizeof headerData;
  written = written && write(fdout, encryptedBuffer, encryptedDataLength) == encryptedDataLength;
  
  if (!written) {
    fprintf(stderr, "Cannot write output file\n");
    return 1;
  }
  
  close(fdout);

  return 0;
}
