package rsniffer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

type SniffConfig struct {
	Device        string
	Snaplen       int32
	Promiscuous   bool
	Timeout       time.Duration
	Filter        string
	PacketProcess func(gopacket.Packet) *PacketInfo
}

type PacketInfo struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
	Payload []byte
	err     error
}

func PacketSniff(snifCfg *SniffConfig, c chan *PacketInfo) error {
	// Open device
	handle, err := pcap.OpenLive(
		snifCfg.Device, snifCfg.Snaplen, snifCfg.Promiscuous, snifCfg.Timeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Set filter
	err = handle.SetBPFFilter(snifCfg.Filter)
	if err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		pinfo := snifCfg.PacketProcess(packet)
		if pinfo != nil {
			c <- pinfo
		}
	}
	return nil
}
