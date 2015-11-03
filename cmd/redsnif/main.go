package main

import (
	"fmt"
	redsnif "github.com/amyangfei/redsnif/sniffer"
	"strings"
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
		PacketProcess: redsnif.PacketProcess,
	}
	c := make(chan *redsnif.PacketInfo)
	go func() {
		if err := redsnif.PacketSniff(Config, c); err != nil {
			panic(err)
		}
	}()
	for {
		info := <-c
		payload := string(info.Payload)
		payload = strings.Replace(payload, "\r", "\\r", -1)
		payload = strings.Replace(payload, "\n", "\\n", -1)
		fmt.Printf("src %s:%d dst %s:%d payload %s\n",
			info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, payload)
	}
}
