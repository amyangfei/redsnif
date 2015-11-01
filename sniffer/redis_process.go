package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func processIPLayer(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
	}
}

func processTCPLayer(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
	}
}

func PacketProcess(packet gopacket.Packet) {
	// application Layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())

		processTCPLayer(packet)
		processIPLayer(packet)
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("packet error:", err)
	}
}

func ProcessPacketSource(packetSource *gopacket.PacketSource) {
	for packet := range packetSource.Packets() {
		PacketProcess(packet)
	}
}
