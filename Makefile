sslkill.dylib: sslkill.c Makefile
	clang -arch i386 -arch x86_64 -O3 -dynamiclib -o sslkill.dylib sslkill.c -framework Security
clean:
	rm -f sslkill.dylib
