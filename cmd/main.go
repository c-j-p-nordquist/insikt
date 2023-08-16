package main

import (
	"fmt"
	"insikt/pkg"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metrics definition
var (
	totalPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "total_packets",
			Help: "Total number of packets processed",
		},
		[]string{"interface"},
	)

	totalBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "total_bytes",
			Help: "Total bytes processed",
		},
		[]string{"interface"},
	)

	uniqueIPs = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "unique_ips",
		Help: "Number of unique IPs",
	})

	uniquePorts = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "unique_ports",
		Help: "Number of unique ports",
	})

	packetDrops = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "packet_drops",
		Help: "Number of packet drops",
	})
)

func init() {
	// Register metrics with Prometheus's default registry
	prometheus.MustRegister(totalPackets, totalBytes, uniqueIPs, uniquePorts, packetDrops)
}

func main() {
	sniffer := pkg.NewSniffer("en0")
	dataProcessor := pkg.NewDataProcessor()

	// Connecting sniffer's PacketChan to dataProcessor's PChan
	sniffer.PacketChan = dataProcessor.PChan

	// Start packet capture in a new goroutine
	go func() {
		err := sniffer.Start()
		if err != nil {
			fmt.Println("Error starting sniffer:", err)
			os.Exit(1)
		}
	}()

	// Start data processing in another goroutine
	go dataProcessor.Start()

	// Periodically print and update statistics in a new goroutine
	go func() {
		for {
			time.Sleep(10 * time.Second) // Print every 10 seconds
			totalPacketsVal, totalBytesVal, uniqueIPsVal, uniquePortsVal, packetDropsVal := dataProcessor.GetMetrics()

			// Update Prometheus metrics
			totalPackets.WithLabelValues("en0").Add(float64(totalPacketsVal))
			totalBytes.WithLabelValues("en0").Add(float64(totalBytesVal))
			uniqueIPs.Set(float64(uniqueIPsVal))
			uniquePorts.Set(float64(uniquePortsVal))
			packetDrops.Set(float64(packetDropsVal))

			fmt.Printf("Processed %d packets, %d bytes. Unique IPs: %d, Unique Ports: %d, Packet Drops: %d\n",
				totalPacketsVal, totalBytesVal, uniqueIPsVal, uniquePortsVal, packetDropsVal)
		}
	}()

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":2112", nil)

	// Capture exit signals to ensure resources are closed correctly
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		sniffer.Stop()
		dataProcessor.Stop()
		os.Exit(0)
	}()

	select {} // Block forever
}
