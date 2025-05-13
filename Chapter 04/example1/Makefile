CC = clang
CFLAGS = -Wall -O2 -g -I/usr/include
LDFLAGS = -lbpf
SRC = bpf_bytecode.c
OUT = bpf_prog

all: $(OUT)

$(OUT): $(SRC)
	gcc -Wall -o $(OUT) $(SRC) -L../../../libbpf/src -l:libbpf.a -lelf -lz

clean:
	rm -f $(OUT)
