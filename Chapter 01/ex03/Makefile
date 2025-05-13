all: seccomp.o

clean:
	rm -f seccomp.o

seccomp.o: seccomp.c
	gcc seccomp.c -o seccomp.o -lpcap