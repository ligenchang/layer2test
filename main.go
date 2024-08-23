package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketProcessor defines an interface for processing packets
type PacketProcessor interface {
	ProcessPacket(packet gopacket.Packet)
}

// EthernetProcessor implements PacketProcessor for Ethernet packets
type EthernetProcessor struct{}

func (ep *EthernetProcessor) ProcessPacket(packet gopacket.Packet) {
	processEthernetLayer(packet)
}

// LatencyJitterStats holds latency and jitter statistics
type LatencyJitterStats struct {
	PreviousTimestamp time.Time
	Latencies         []time.Duration
	Jitters           []time.Duration
}

var stats struct {
	TotalPackets    int
	EthernetPackets int
	ARPPackets      int
	IPv4Packets     int
	LatencyJitter   LatencyJitterStats
}

// CapturePackets captures packets from the network interface and processes them
func CapturePackets(device, filter, outputFile string, processor PacketProcessor, timeout time.Duration) error {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("error setting BPF filter: %v", err)
		}
	}

	var file *os.File
	if outputFile != "" {
		file, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error creating output file: %v", err)
		}
		defer file.Close()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Println("Starting packet capture...")

	packetCount := 0
	timeoutChan := time.After(timeout)

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				return nil
			}
			packetCount++
			stats.TotalPackets++
			timestamp := packet.Metadata().Timestamp
			log.Printf("Packet %d at %s:", packetCount, timestamp.Format(time.RFC3339))

			if file != nil {
				file.Write(packet.Data())
			}

			// Calculate latency and jitter
			if !stats.LatencyJitter.PreviousTimestamp.IsZero() {
				latency := timestamp.Sub(stats.LatencyJitter.PreviousTimestamp)
				stats.LatencyJitter.Latencies = append(stats.LatencyJitter.Latencies, latency)

				if len(stats.LatencyJitter.Latencies) > 1 {
					jitter := latency - stats.LatencyJitter.Latencies[len(stats.LatencyJitter.Latencies)-2]
					stats.LatencyJitter.Jitters = append(stats.LatencyJitter.Jitters, jitter)
				}
			}
			stats.LatencyJitter.PreviousTimestamp = timestamp

			processor.ProcessPacket(packet)
		case <-timeoutChan:
			log.Println("Packet capture timeout reached.")
			return nil
		}
	}
}

func processEthernetLayer(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}

	stats.EthernetPackets++

	ethPacket, ok := ethernetLayer.(*layers.Ethernet)
	if !ok {
		log.Printf("  Error asserting Ethernet layer type")
		return
	}

	logEthernetLayer(ethPacket)
	processVLANLayer(packet)
	processLLDPLayer(packet)
	processEthernetType(packet, ethPacket)
}

func logEthernetLayer(ethPacket *layers.Ethernet) {
	log.Printf("  Ethernet Layer:")
	log.Printf("    Source MAC: %s", ethPacket.SrcMAC)
	log.Printf("    Destination MAC: %s", ethPacket.DstMAC)
	log.Printf("    Ethernet Type: %s", ethPacket.EthernetType)
	log.Printf("    Length: %d", len(ethPacket.Payload))
	log.Printf("    Payload: %x", ethPacket.Payload)

	srcMACParts := strings.Split(ethPacket.SrcMAC.String(), ":")
	log.Printf("    Source MAC Parts: %v", srcMACParts)

	dstMACParts := strings.Split(ethPacket.DstMAC.String(), ":")
	log.Printf("    Destination MAC Parts: %v", dstMACParts)
}

func processVLANLayer(packet gopacket.Packet) {
	vlanLayer := packet.Layer(layers.LayerTypeDot1Q)
	if vlanLayer != nil {
		vlanPacket, ok := vlanLayer.(*layers.Dot1Q)
		if !ok {
			log.Printf("  Error asserting VLAN layer type")
			return
		}
		log.Printf("  VLAN Layer:")
		log.Printf("    Priority Code Point: %d", vlanPacket.Priority)
		log.Printf("    VLAN Identifier: %d", vlanPacket.VLANIdentifier)
		log.Printf("    EtherType: %s", vlanPacket.Type)
	}
}

func processLLDPLayer(packet gopacket.Packet) {
	// Process LLDP layer if present
	lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery)
	if lldpLayer != nil {
		lldpPacket, ok := lldpLayer.(*layers.LinkLayerDiscovery)
		if !ok {
			log.Printf("  Error asserting LLDP layer type")
			return
		}
		log.Printf("  LLDP Layer detected")
		log.Printf("    Chassis ID: %s", lldpPacket.ChassisID)
		log.Printf("    Port ID: %s", lldpPacket.PortID)
		log.Printf("    TTL: %d", lldpPacket.TTL)
		// log.Printf("    System Name: %s", lldpPacket.SystemName)
		// log.Printf("    System Description: %s", lldpPacket.SystemDescription)
	}
}

func processEthernetType(packet gopacket.Packet, ethPacket *layers.Ethernet) {
	switch ethPacket.EthernetType {
	case layers.EthernetTypeARP:
		stats.ARPPackets++
		log.Printf("  ARP Packet detected")
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arpPacket, ok := arpLayer.(*layers.ARP)
			if !ok {
				log.Printf("  Error asserting ARP layer type")
				return
			}
			log.Printf("  ARP Layer:")
			log.Printf("    Source IP: %s", arpPacket.SourceProtAddress)
			log.Printf("    Destination IP: %s", arpPacket.DstProtAddress)
			log.Printf("    Operation: %d", arpPacket.Operation)
		}
	case layers.EthernetTypeIPv4:
		stats.IPv4Packets++

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ipPacket, ok := ipLayer.(*layers.IPv4)
			if !ok {
				log.Printf("  Error asserting IP layer type")
				return
			}
			log.Printf("  IPv4 Layer:")
			log.Printf("    Source IP: %s", ipPacket.SrcIP)
			log.Printf("    Destination IP: %s", ipPacket.DstIP)
			log.Printf("    Protocol: %s", ipPacket.Protocol)
			log.Printf("    TTL: %d", ipPacket.TTL)
		}
	}
}

func main() {
	device := flag.String("device", "en0", "Network device to capture packets from")
	filter := flag.String("filter", "", "BPF filter for packet capture")
	outputFile := flag.String("output", "", "File to save captured packets")
	timeout := flag.Duration("timeout", 10*time.Second, "Duration to capture packets before stopping")
	flag.Parse()

	processor := &EthernetProcessor{}
	if err := CapturePackets(*device, *filter, *outputFile, processor, *timeout); err != nil {
		log.Fatalf("Error capturing packets: %v", err)
	}

	log.Printf("Packet capture complete. Statistics:")
	log.Printf("  Total Packets: %d", stats.TotalPackets)
	log.Printf("  Ethernet Packets: %d", stats.EthernetPackets)
	log.Printf("  ARP Packets: %d", stats.ARPPackets)
	log.Printf("  IPv4 Packets: %d", stats.IPv4Packets)

	if len(stats.LatencyJitter.Latencies) > 0 {
		var totalLatency time.Duration
		for _, latency := range stats.LatencyJitter.Latencies {
			totalLatency += latency
		}
		averageLatency := totalLatency / time.Duration(len(stats.LatencyJitter.Latencies))
		log.Printf("  Average Latency: %v", averageLatency)
	}

	if len(stats.LatencyJitter.Jitters) > 0 {
		var totalJitter time.Duration
		for _, jitter := range stats.LatencyJitter.Jitters {
			totalJitter += jitter
		}
		averageJitter := totalJitter / time.Duration(len(stats.LatencyJitter.Jitters))
		log.Printf("  Average Jitter: %v", averageJitter)
	}
}
