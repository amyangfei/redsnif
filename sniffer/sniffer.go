package sniffer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
)

type SniffConfig struct {
	Device        string
	Snaplen       int32
	Promiscuous   bool
	Timeout       time.Duration
	Filter        string
	PacketProcess func(*gopacket.PacketSource)
}

func PacketSniff(snifCfg *SniffConfig) error {
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
	snifCfg.PacketProcess(packetSource)
	return nil
}
