# Network Analyzer

This project consists of two applications: a CLI application and a packet analyzer.

### CLI Application

The CLI application allows users to interact with the packet analyzer. It provides commands to start, stop, and exit the packet capture process. Additionally, it now includes the ability to toggle packet capture start and stop with the 'S' key and save captured packets by pressing ENTER.

### Packet Analyzer

The packet analyzer captures TCP packets, analyzes them, and calculates various parameters such as throughput, retransmitted packets, and packet loss rate.

#### Parameters Calculated:
- **Throughput:** Measures the data transfer rate in Mbps.
- **Retransmitted Packets:** Tracks the number of TCP packets that are retransmitted.
- **Packet Loss Rate:** Calculates the percentage of packets lost during transmission.

### Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/network-analyzer.git
