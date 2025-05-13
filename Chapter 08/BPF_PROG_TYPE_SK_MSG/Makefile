TARGET = sk_msg
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

all: $(BPF_OBJ)
.PHONY: all

%.bpf.o: %.bpf.c vmlinux.h
	clang \
	    -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
