#ifndef _Common_h_included_
#define _Common_h_included_

#include <stdint.h>

struct header
{
	char magic[4]; 			// magic bytes \x43 \x46 \x47 \x31 (CFG1)
	uint32_t payload_size; 	// length of ciphertext = length of padded plaintext (big endian)
	uint8_t header_md5[8];		// first 8 bytes of MD5 computed over header (assuming the 8 bytes of "header_md5" are \x00)
	char etl[7]; 			// blank electronic label (etl), always "000000" (null-terminated char array)
	uint8_t unused1; 			// not used at the moment
	uint16_t password_len; 	// length of the password used in AES encryption (big endian)
	uint16_t padding_len; 	// number of padding bytes added to plaintext (big endian)
	uint8_t unused2[4];		// not used at the moment
	uint8_t plaintext_md5[16]; // MD5 hash of the plaintext
};

static const char aes_key[32] = {
  0x64, 0x75, 0x6d, 0x6d, 0x79, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

enum {
  HeaderSize = 48
};

#endif
