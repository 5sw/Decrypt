/* Copyright (c) 2013 Sven Weidauer
 * Code is under the MIT license, see the LICENSE file.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCrypto.h>
#include <sys/stat.h>
#include <sys/mman.h>

struct header
{
	char magic[4]; 			// magic bytes \x43 \x46 \x47 \x31 (CFG1)
	uint32_t payload_size; 	// length of ciphertext = length of padded plaintext (big endian)
	char header_md5[8];		// first 8 bytes of MD5 computed over header (assuming the 8 bytes of "header_md5" are \x00)
	char etl[7]; 			// blank electronic label (etl), always "000000" (null-terminated char array)
	char unused1; 			// not used at the moment
	uint16_t password_len; 	// length of the password used in AES encryption (big endian)
	uint16_t padding_len; 	// number of padding bytes added to plaintext (big endian)
	char unused2[4];		// not used at the moment
	char plaintext_md5[16]; // MD5 hash of the plaintext
};

static const char aes_key[32] = {
	0x64, 0x75, 0x6d, 0x6d, 0x79, 0x00, 0x00, 0x00,
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


struct buffer {
	uint8_t *start;
	size_t length;
	uint8_t *next;
	int fd;
};

void Read( struct buffer *buf, size_t length, void *destination )
{
	assert( buf->next + length < buf->start + buf->length );
	memcpy( destination, buf->next, length );
	buf->next += length;
}

uint32_t Read32( struct buffer *buf )
{
	uint32_t result;
	Read( buf, sizeof result, &result );
	return CFSwapInt32BigToHost( result );
}

uint16_t Read16( struct buffer *buf )
{
	uint16_t result;
	Read( buf, sizeof result, &result );
	return CFSwapInt16BigToHost( result );
}

void ReadHeader( struct buffer *buf, struct header *header )
{
	Read( buf, 4, header->magic );
	header->payload_size = Read32( buf );
	Read( buf, 8, header->header_md5 );
	Read( buf, 7, header->etl );
	Read( buf, 1, &header->unused1 );
	header->password_len = Read16( buf );
	header->padding_len = Read16( buf );
	Read( buf, 4, header->unused2 );
	Read( buf, 16, header->plaintext_md5 );
}

bool OpenFile( struct buffer *buf, const char *fn )
{
	buf->fd = open( fn, O_RDONLY );
	if (buf->fd < 0) return false;
	
	struct stat stat;
	if (fstat( buf->fd, &stat ) < 0) {
		close( buf->fd );
		return false;
	}
	
	buf->length = stat.st_size;
	
	buf->start = mmap( NULL, buf->length, PROT_READ, MAP_FILE | MAP_PRIVATE, buf->fd, 0 );
	if (!buf->start) {
		close( buf->fd );
		return false;
	}
	
	buf->next = buf->start;
	
	return true;
}

int main( int argc, const char *argv[] ) 
{
	if (argc != 3) {
		fprintf( stderr, "Call %s <input> <output>\n", argv[0] );
		return 1;
	}
	
	struct buffer buf = { 0 };
	
	if (!OpenFile( &buf, argv[1] )) {
		fprintf( stderr, "Cannot open file %s\n", argv[1] );
		return 1;
	}
	
	printf( "Openend file, size: %zu\n", buf.length );
	
	struct header header = { 0 };
	ReadHeader( &buf, &header );

	if (memcmp( header.magic, "CFG1", 4 ) != 0) {
		fprintf( stderr, "Error: invalid magic\n" );
		return 1;
	}
	
	char header_data[48];
	memcpy( header_data, buf.start, sizeof header_data );
	memset( &header_data[8], 0, 8 );
	
	unsigned char header_md[CC_MD5_DIGEST_LENGTH];
	CC_MD5( header_data, sizeof header_data, header_md );
	if (memcmp( header.header_md5, header_md, sizeof header.header_md5 ) != 0) {
		printf( "Warning: Header MD5 doesn't match\n" );
	}
	
	printf( "Payload size: %d\n", header.payload_size );
	printf( "Padding: %d\n", header.padding_len );
	printf( "Password len: %d\n", header.password_len );
	printf( "ETL: %s\n", header.etl );
	
	if (buf.length - header.payload_size != 48) {
		fprintf( stderr, "Error: Invalid file size\n" );
		return 1;
	}
	
	size_t plain_length = header.payload_size;
	void *plain = malloc( plain_length );
	if (!plain) {
		fprintf( stderr, "Error: Not enough memory for decryption\n" );
		return 1;
	}
	
	CCCryptorRef cryptor;
	size_t result_length = 0;
	if (CCCrypt( kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode, aes_key, sizeof aes_key, NULL, buf.next, plain_length, plain, plain_length, &result_length ) != kCCSuccess) {
		fprintf( stderr, "Error: Cannot decrypt\n" );
		return 1;
	}
	
	result_length -= header.padding_len;
	
	int fdout = open( argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600 );
	if (fdout < 0) {
		fprintf( stderr, "Error: cannot write output file\n" );
		return 1;
	}
	if (write( fdout, plain, result_length  ) != result_length) {
		fprintf( stderr, "Error: cannot write output file\n" );
		return 1;
	}
	close( fdout );
	
	unsigned char md[CC_MD5_DIGEST_LENGTH];
	CC_MD5( plain, plain_length, md );

	if (memcmp( md, header.plaintext_md5, sizeof md ) != 0) {
		printf( "Warning: payload md5 doesn't match\n" );
	}
}