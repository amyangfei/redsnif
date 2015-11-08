package main

import (
	"encoding/hex"
	"fmt"
	redsnif "github.com/amyangfei/redsnif/rsniffer"
	"strings"
	"time"
)

var Config *redsnif.SniffConfig

func main() {
	Config = &redsnif.SniffConfig{
		Device:      "lo",
		Snaplen:     1500,
		Promiscuous: true,
		Timeout:     time.Duration(time.Second * 5),
		Host:        "127.0.0.1",
		Port:        6379,
		UseZeroCopy: true,
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
		fmt.Printf("src %s:%d dst %s:%d payload %s seq %d sessionid %s\n",
			info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, payload,
			info.Seq, hex.EncodeToString(info.SessionID))
	}
}
