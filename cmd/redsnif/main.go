package main

import (
	redsnif "github.com/amyangfei/redsnif/sniffer"
	"time"
)

var Config *redsnif.SniffConfig

func main() {
	Config = &redsnif.SniffConfig{
		Device:        "lo",
		Snaplen:       1500,
		Promiscuous:   true,
		Timeout:       time.Duration(time.Second * 5),
		Filter:        "tcp and port 6379",
		PacketProcess: redsnif.ProcessPacketSource,
	}
	if err := redsnif.PacketSniff(Config); err != nil {
		panic(err)
	}
}
