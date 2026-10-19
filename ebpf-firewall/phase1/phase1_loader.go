package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	pinPath        = "/sys/fs/bpf"
	rulesMapName   = "firewall_rules"
	statsMapName   = "firewall_stats"
	statLabelTotal = 0
	statLabelDrop  = 1
	statLabelAllow = 2
	statLabelICMP  = 3
)

func defaultObjectPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "phase1_packet_filter.o"
	}
	return filepath.Join(filepath.Dir(exe), "phase1_packet_filter.o")
}

func main() {
	ifaceName := flag.String("interface", "eth0", "network interface to attach XDP program to")
	objPath := flag.String("object", defaultObjectPath(), "path to compiled eBPF object file")
	statsInterval := flag.Duration("stats", 5*time.Second, "interval for printing stats (0 disables)")
	driverMode := flag.Bool("driver-mode", false, "attach with native XDP driver mode (requires NIC support); default is generic SKB mode")
	flag.Parse()

	// Linux permits only one active XDP program per interface. The packet filter
	// and the event monitor are intentionally modeled as separate phases, but they
	// cannot both attach to the same NIC at once in a real kernel configuration.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	if err := os.MkdirAll(pinPath, 0755); err != nil {
		log.Fatalf("ensuring bpf fs pin dir: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("loading collection spec from %s: %v", *objPath, err)
	}

	for name, m := range spec.Maps {
		if name == rulesMapName || name == statsMapName {
			m.Pinning = ebpf.PinByName
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	})
	if err != nil {
		log.Fatalf("creating eBPF collection: %v", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["xdp_packet_filter"]
	if !ok {
		log.Fatalf("program 'xdp_packet_filter' not found in object file")
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("looking up interface %s: %v", *ifaceName, err)
	}

	xdpFlags := link.XDPGenericMode
	modeName := "generic"
	if *driverMode {
		xdpFlags = link.XDPDriverMode
		modeName = "driver"
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     xdpFlags,
	})
	if err != nil {
		log.Fatalf("attaching XDP program to %s: %v", *ifaceName, err)
	}
	defer l.Close()

	fmt.Printf(" Phase 1 packet filter attached to %s (XDP %s mode)\n", *ifaceName, modeName)
	fmt.Printf("   Rules map pinned at %s/%s\n", pinPath, rulesMapName)
	fmt.Printf("   Stats map pinned at %s/%s\n", pinPath, statsMapName)
	fmt.Println("   Press Ctrl+C to detach and exit.")

	statsMap := coll.Maps[statsMapName]

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var ticker *time.Ticker
	var tickCh <-chan time.Time
	if *statsInterval > 0 {
		ticker = time.NewTicker(*statsInterval)
		tickCh = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
		case <-sigCh:
			fmt.Println("\nDetaching XDP program and exiting...")
			return
		case <-tickCh:
			printStats(statsMap)
		}
	}
}

func printStats(statsMap *ebpf.Map) {
	labels := map[uint32]string{
		statLabelTotal: "total",
		statLabelDrop:  "dropped",
		statLabelAllow: "allowed",
		statLabelICMP:  "icmp_dropped",
	}
	fmt.Printf("[%s] stats: ", time.Now().Format(time.RFC3339))
	for idx := uint32(0); idx < 8; idx++ {
		var val uint64
		if err := statsMap.Lookup(&idx, &val); err == nil {
			fmt.Printf("%s=%d ", labels[idx], val)
		}
	}
	fmt.Println()
}
