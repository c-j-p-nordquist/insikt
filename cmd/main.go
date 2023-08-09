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
			fmt.Printf("Packet: SrcIP: %s, DstIP: %s, Layer: %s, Protocol: %s, SrcPort: %d, DstPort: %d\n",
				packet.SrcIP, packet.DstIP, packet.LayerType, packet.Protocol, packet.SrcPort, packet.DstPort)
			// If HTTP headers are captured, you can display them too
			if len(packet.HTTPHeaders) > 0 {
				fmt.Println("HTTP Headers:", packet.HTTPHeaders)
			}
		}
	}()

	// Capture exit signals to ensure resources are closed correctly
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nReceived an interrupt, stopping...")
		sniffer.Stop()
		close(sniffer.PacketChan) // Ensure to close the packet channel after stopping the sniffer
		os.Exit(0)
	}()

	select {} // Block the main thread forever
}
