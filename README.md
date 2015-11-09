# Decrypt

Decrypt saved config data from some Sphairon routers (such as the Alice IAD 3232 or similar models) on Mac OS X.

Thanks to [hph][1] for reverse engineering the details of that config format.

## Compile:

	make

## Run:

	Decrypt path/to/config.bin path/to/output.tgz
	Encrypt path/to/output.tgz path/to/new/config.bin

[1]: http://hph.name/207
