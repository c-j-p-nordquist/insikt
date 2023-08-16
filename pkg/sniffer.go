package pkg

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketData defines a structure for relevant fields from the captured packet.
type PacketData struct {
	SrcIP       string             // Source IP address
	DstIP       string             // Destination IP address
	LayerType   gopacket.LayerType // IPv4, IPv6, etc.
	Protocol    layers.IPProtocol  // Protocol Type (TCP, UDP, etc.)
	SrcPort     int                // Source port number
	DstPort     int                // Destination port number
	Payload     []byte             // Packet payload (actual data)
	HTTPHeaders map[string]string  // HTTP headers, if applicable
	SeqNum      uint32             // TCP sequence number (only for TCP packets)

}

// TrafficStats defines a structure to capture global packet statistics.
type TrafficStats struct {
	TotalPackets int64 // Total number of packets captured
	TotalBytes   int64 // Total bytes processed from all packets
}

// Sniffer captures packets from a network interface and parses relevant data.
type Sniffer struct {
	handle     *pcap.Handle    // Handle for the pcap packet capture session
	source     string          // Network interface source, e.g., "en0" for macOS
	PacketChan chan PacketData // Buffered channel to store parsed packet data
	Stats      TrafficStats    // Structure to capture traffic statistics
}

// NewSniffer initializes a new Sniffer with a given source (network interface).
func NewSniffer(source string) *Sniffer {
	return &Sniffer{
		source:     source,
		PacketChan: make(chan PacketData, 1000), // Initializing a buffered channel with capacity of 1000 packets.
	}
}

// Start begins the packet capture and parses relevant data from each packet.
func (s *Sniffer) Start() error {
	var err error
	s.handle, err = pcap.OpenLive(s.source, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for packet := range packetSource.Packets() {
		s.parsePacket(packet) // For each captured packet, parse relevant data.
	}

	return nil
}

// Stop ends the packet capture session.
func (s *Sniffer) Stop() {
	if s.handle != nil {
		s.handle.Close()
	}
}

// parsePacket processes each packet to extract relevant fields and updates traffic statistics.
func (s *Sniffer) parsePacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		packetData := PacketData{
			SrcIP:     ip.SrcIP.String(),
			DstIP:     ip.DstIP.String(),
			LayerType: layers.LayerTypeIPv4,
			Protocol:  ip.Protocol,
		}

		switch ip.Protocol {
		case layers.IPProtocolTCP:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				packetData.SrcPort = int(tcp.SrcPort)
				packetData.DstPort = int(tcp.DstPort)
				packetData.Payload = tcp.Payload
				packetData.SeqNum = uint32(tcp.Seq) // Capture the sequence number

				// Capture HTTP headers if payload is HTTP
				if httpLayer := packet.ApplicationLayer(); httpLayer != nil {
					headers := make(map[string]string)
					packetData.HTTPHeaders = headers
				}
			}
		case layers.IPProtocolUDP:
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				packetData.SrcPort = int(udp.SrcPort)
				packetData.DstPort = int(udp.DstPort)
				packetData.Payload = udp.Payload
			}
		}

		// Send parsed packet data to the channel
		s.PacketChan <- packetData
	}

	// Update global traffic statistics
	s.Stats.TotalPackets++
	s.Stats.TotalBytes += int64(len(packet.Data()))
}
