package rsniffer

import (
	"fmt"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
)

type Sniffer struct {
	Config   *SniffConfig
	RCounter int64
	WCounter int64
	RSize    int64
	WSize    int64
}

type SniffConfig struct {
	Device      string
	Snaplen     int32
	Promiscuous bool
	Timeout     time.Duration
	UseZeroCopy bool
	Host        string
	Port        int
	MaxBufSize  int
	AzConfig    *AnalyzeConfig
}

func NewSniffer(config *SniffConfig) *Sniffer {
	return &Sniffer{
		Config:   config,
		RCounter: 0,
		WCounter: 0,
		RSize:    0,
		WSize:    0,
	}
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
		MaxBufSize:  10240,
		AzConfig: &AnalyzeConfig{
			ReadHitAnalyze: true,
			SaveCmdTypes:   []int{RedisCmdRead},
			SaveDetail:     RecordCmdOnly,
		},
	}
}

func (s *Sniffer) PacketSniff(c chan *RedSession, ec chan error) {
	config := s.Config
	// Open device
	handle, err := pcap.OpenLive(
		config.Device, config.Snaplen, config.Promiscuous, config.Timeout)
	if err != nil {
		ec <- err
		return
	}
	defer handle.Close()

	// Set filter
	filter := fmt.Sprintf("host %s and port %d", config.Host, config.Port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		ec <- err
		return
	}

	sp := NewRedSessionPool()

	ticker := time.NewTicker(time.Second * 2)
	go func() {
		for _ = range ticker.C {
			fmt.Printf("rcounter: %d wcounter: %d rsize: %d wsize: %d\n", s.RCounter, s.WCounter, s.RSize, s.WSize)
		}
	}()

	if config.UseZeroCopy {
		packetSource := NewZeroCopyPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			rs, err := PacketProcess(packet, sp, s)
			if err != nil {
				ec <- err
			} else if rs != nil {
				c <- rs
			}
		}
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			rs, err := PacketProcess(packet, sp, s)
			if err != nil {
				ec <- err
			} else if rs != nil {
				c <- rs
			}
		}
	}
}
