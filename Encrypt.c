#include "Buffer.h"
#include "Common.h"

#include <stdio.h>

int main( int argc, const char *argv[] ) 
{
	if (argc != 3) {
		fprintf( stderr, "Call %s <input> <output>\n", argv[0] );
		return 1;
	}
  
  return 0;
}
