package rsniffer

import (
	"fmt"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
)

type SniffConfig struct {
	Device      string
	Snaplen     int32
	Promiscuous bool
	Timeout     time.Duration
	Host        string
	Port        int
	UseZeroCopy bool
	AzConfig    *AnalyzeConfig
}

func DefaultSniffConfig() *SniffConfig {
	return &SniffConfig{
		Device:      "eth0",
		Snaplen:     1500,
		Promiscuous: true,
		Timeout:     time.Duration(3 * time.Second),
		UseZeroCopy: true,
		Host:        "127.0.0.1",
		Port:        6379,
		AzConfig: &AnalyzeConfig{
			ReadHitAnalyze: true,
			SaveCmdTypes:   []int{RedisCmdRead},
			SaveDetail:     RecordCmdOnly,
		},
	}
}

func PacketSniff(snifCfg *SniffConfig, c chan *PacketInfo, ec chan error) {
	// Open device
	handle, err := pcap.OpenLive(
		snifCfg.Device, snifCfg.Snaplen, snifCfg.Promiscuous, snifCfg.Timeout)
	if err != nil {
		ec <- err
		return
	}
	defer handle.Close()

	// Set filter
	filter := fmt.Sprintf("host %s and port %d", snifCfg.Host, snifCfg.Port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		ec <- err
		return
	}

	sp := NewSessionPool()

	if snifCfg.UseZeroCopy {
		packetSource := NewZeroCopyPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			pinfo := PacketProcess(packet, sp, snifCfg)
			if pinfo != nil {
				c <- pinfo
			}
		}
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			pinfo := PacketProcess(packet, sp, snifCfg)
			if pinfo != nil {
				c <- pinfo
			}
		}
	}
}
