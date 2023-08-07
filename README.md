# Insikt - Network Sniffer

A lightweight network sniffer designed to capture and process network packets for analytics.

## Modules

### 1. Data Capture Module:
- **Purpose**: Captures raw network data.
- **Components**:
  - Packet Sniffer: Captures raw packets.
  - Traffic Monitor: Monitors network traffic statistics.
- **Output**: Streams of raw packets and traffic data.

### 2. Data Processing Module:
... (in development)

## Getting Started

1. Clone this repository.
2. Navigate to the project directory.
3. Run `go build cmd/main.go` to compile the sniffer.
4. Execute the binary to start the sniffer: `./main`

## Future Enhancements
- Integrate with Prometheus for longer-term data storage.
- Develop a web-based dashboard for real-time analytics.

## Contributors
- Philip Nordquist @c-j-p-nordquist
