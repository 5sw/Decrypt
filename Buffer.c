#include "Buffer.h"

#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>

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

void OpenBuffer( struct buffer *buf, void *data, size_t length )
{
  buf->start = buf->next = data;
  buf->length = length;
  buf->fd = -1;
}

void Write( struct buffer *buf, const void *data, size_t length )
{
  memcpy(buf->next, data, length);
  buf->next += length;
}

void Write32( struct buffer *buf, uint32_t value )
{
  uint32_t write = CFSwapInt32HostToBig(value);
  Write(buf, &write, sizeof write);
}

void Write16( struct buffer *buf, uint16_t value )
{
  uint16_t write = CFSwapInt16HostToBig(value);
  Write(buf, &write, sizeof write);
}
