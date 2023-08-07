package main

import (
	"fmt"
	"insikt/pkg"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	sniffer := pkg.NewSniffer("en0") // Replace "en0" with your network interface

	// Start packet capture in a new goroutine
	go func() {
		err := sniffer.Start()
		if err != nil {
			fmt.Println("Error starting sniffer:", err)
			os.Exit(1)
		}
	}()

	// Handle the packets in another goroutine
	go func() {
		for packet := range sniffer.PacketChan {
			fmt.Printf("Packet: SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d\n",
				packet.SrcIP, packet.DstIP, packet.SrcPort, packet.DstPort)
			// You can add more processing here as needed
		}
	}()

	// Capture exit signals to ensure resources are closed correctly
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		sniffer.Stop()
		close(sniffer.PacketChan) // Closing the packet channel once we're done
		os.Exit(0)
	}()

	select {} // Block forever
}
