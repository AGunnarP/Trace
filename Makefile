trace: trace.c
	gcc -lpcap -g -o trace trace.c checksum.c
