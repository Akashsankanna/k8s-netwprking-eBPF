package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type packetEvent struct {
	TimestampNs uint64
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Verdict     uint8
	PktLen      uint16
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("proto(%d)", p)
	}
}

func ipString(be uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, be)
	addr := netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	return addr.String()
}

func defaultObjectPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "phase2_ringbuf_events.o"
	}
	return filepath.Join(filepath.Dir(exe), "phase2_ringbuf_events.o")
}

func main() {
	ifaceName := flag.String("interface", "eth0", "network interface to attach to")
	objPath := flag.String("object", defaultObjectPath(), "path to compiled eBPF object file")
	statsInterval := flag.Duration("stats", 5*time.Second, "interval for throughput summary")
	quiet := flag.Bool("quiet", false, "suppress per-packet lines, show only periodic stats")
	driverMode := flag.Bool("driver-mode", false, "attach with native XDP driver mode; default is generic SKB mode")
	flag.Parse()

	// Linux permits only one active XDP program per interface. In practice, this
	// monitor should be run on a different NIC than phase1, or phase1 must be
	// detached before it can be attached here.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("loading collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating eBPF collection: %v", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["xdp_event_monitor"]
	if !ok {
		log.Fatalf("program 'xdp_event_monitor' not found in object file")
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("looking up interface %s: %v", *ifaceName, err)
	}

	xdpFlags := link.XDPGenericMode
	if *driverMode {
		xdpFlags = link.XDPDriverMode
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     xdpFlags,
	})
	if err != nil {
		log.Fatalf("attaching XDP program: %v", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("opening ring buffer reader: %v", err)
	}
	defer rd.Close()

	fmt.Printf(" Phase 2 event monitor attached to %s\n", *ifaceName)
	fmt.Println("   Streaming packet events... Ctrl+C to stop.")

	var totalEvents, totalBytes uint64

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		rd.Close() // unblocks rd.Read() below
	}()

	go func() {
		ticker := time.NewTicker(*statsInterval)
		defer ticker.Stop()
		for range ticker.C {
			ev := atomic.LoadUint64(&totalEvents)
			bts := atomic.LoadUint64(&totalBytes)
			flowCount := countFlows(coll.Maps["flows"])
			fmt.Printf("[%s] events=%d bytes=%d flows=%d\n",
				time.Now().Format(time.RFC3339), ev, bts, flowCount)
		}
	}()

	var evt packetEvent
	for {
		record, err := rd.Read()
		if err != nil {
			fmt.Println("Event monitor stopped.")
			return
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			continue
		}
		atomic.AddUint64(&totalEvents, 1)
		atomic.AddUint64(&totalBytes, uint64(evt.PktLen))

		if !*quiet {
			fmt.Printf("%s  %-4s %s:%d -> %s:%d  len=%d\n",
				time.Unix(0, int64(evt.TimestampNs)).Format("15:04:05.000"),
				protoName(evt.Protocol),
				ipString(evt.SrcIP), evt.SrcPort,
				ipString(evt.DstIP), evt.DstPort,
				evt.PktLen)
		}
	}
}

func countFlows(m *ebpf.Map) int {
	if m == nil {
		return 0
	}
	it := m.Iterate()
	var key, val []byte
	count := 0
	for it.Next(&key, &val) {
		count++
	}
	return count
}
