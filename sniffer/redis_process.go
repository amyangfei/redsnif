package sniffer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func PacketProcess(packet gopacket.Packet) *PacketInfo {
	// Check application Layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		pinfo := &PacketInfo{
			Payload: applicationLayer.Payload(),
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			pinfo.SrcIP = ip.SrcIP
			pinfo.DstIP = ip.DstIP
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			pinfo.SrcPort = tcp.SrcPort
			pinfo.DstPort = tcp.DstPort
		}
		// Check for errors
		if err := packet.ErrorLayer(); err != nil {
			pinfo.err = err.Error()
		}
		return pinfo
	}
	return nil
}
