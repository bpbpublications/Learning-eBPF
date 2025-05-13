TARGET = load_balance
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_OBJ = ${TARGET:=.bpf.o}


all: $(BPF_OBJ)


%.bpf.o: %.bpf.c
	clang \
	    -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

clean:
	- rm $(BPF_OBJ)
