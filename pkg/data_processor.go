package pkg

import (
	"sync"

	"github.com/google/gopacket/layers"
)

// ProcessedData defines a structure to hold data after processing.
type ProcessedData struct {
	TotalPackets int
	TotalBytes   int
	UniqueIPs    map[string]struct{} // A set for unique IPs
	UniquePorts  map[int]struct{}    // A set for unique ports
	LastSeqNum   map[string]uint32   // A map to store the last sequence number for each SrcIP-DstIP pair
	PacketDrops  int                 // Counter for packet drops
}

// DataProcessor defines a structure to process incoming packets.
type DataProcessor struct {
	mu    sync.Mutex      // Mutex to protect concurrent access
	Data  ProcessedData   // Processed data storage
	PChan chan PacketData // Channel to receive packets
}

// NewDataProcessor initializes a new DataProcessor.
func NewDataProcessor() *DataProcessor {
	return &DataProcessor{
		PChan: make(chan PacketData, 1000),
		Data: ProcessedData{
			UniqueIPs:   make(map[string]struct{}),
			UniquePorts: make(map[int]struct{}),
			LastSeqNum:  make(map[string]uint32),
		},
	}
}

// Start begins the data processing.
func (dp *DataProcessor) Start() {
	for packet := range dp.PChan {
		dp.processPacket(packet)
	}
}

// processPacket processes an individual packet.
func (dp *DataProcessor) processPacket(packet PacketData) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	dp.Data.TotalPackets++
	dp.Data.TotalBytes += len(packet.Payload)

	// Capture unique IPs and ports
	dp.Data.UniqueIPs[packet.SrcIP] = struct{}{}
	dp.Data.UniqueIPs[packet.DstIP] = struct{}{}
	dp.Data.UniquePorts[packet.SrcPort] = struct{}{}
	dp.Data.UniquePorts[packet.DstPort] = struct{}{}

	// Calculate packet drops using TCP sequence numbers
	if packet.Protocol == layers.IPProtocolTCP {
		key := packet.SrcIP + "-" + packet.DstIP
		if lastSeq, exists := dp.Data.LastSeqNum[key]; exists && packet.SeqNum != lastSeq+1 {
			dp.Data.PacketDrops++
		}
		dp.Data.LastSeqNum[key] = packet.SeqNum
	}
}

// GetMetrics retrieves the processed metrics.
func (dp *DataProcessor) GetMetrics() (int, int, int, int, int) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	return dp.Data.TotalPackets, dp.Data.TotalBytes, len(dp.Data.UniqueIPs), len(dp.Data.UniquePorts), dp.Data.PacketDrops
}

// Stop stops the data processing.
func (dp *DataProcessor) Stop() {
	close(dp.PChan)
}
