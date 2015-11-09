#ifndef _Buffer_h_included_
#define _Buffer_h_included_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct buffer {
	uint8_t *start;
	size_t length;
	uint8_t *next;
	int fd;
};

void Read( struct buffer *buf, size_t length, void *destination );
uint32_t Read32( struct buffer *buf );
uint16_t Read16( struct buffer *buf );

void Write( struct buffer *buf, const void *data, size_t length );
void Write32( struct buffer *buf, uint32_t value );
void Write16( struct buffer *buf, uint16_t value );

void OpenBuffer( struct buffer *buf, void *data, size_t length );

bool OpenFile( struct buffer *buf, const char *fn );

#endif
