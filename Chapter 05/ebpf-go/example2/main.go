package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf kprobe.bpf.c -- -I../headers

func main() {
	// Name of the kernel function to trace.
	fn := "sys_clone"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load the pre-compiled program into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program.
	kp, err := link.Kprobe(fn, objs.BpfProg1, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	log.Println("Kprobe attached. Waiting for events (Ctrl+C to exit)...")

	// Handle Ctrl+C signal for graceful shutdown
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	// Keep running until Ctrl+C is pressed
	<-sigchan

	var value uint64

	for i := uint32(0); i < 8192; i++ { // Iterate up to max_entries
		if err := objs.OpenatCount.Lookup(i, &value); err == nil { // Check for existence
			fmt.Printf("PID: %d, Count: %d\n", i, value)
		} // No else needed, we just skip non-existent keys
	}
}
