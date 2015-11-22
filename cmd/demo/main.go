package main

import (
	// "encoding/hex"
	// "fmt"
	"github.com/Sirupsen/logrus"
	"github.com/amyangfei/redsnif/datahub"
	redsnif "github.com/amyangfei/redsnif/rsniffer"
	"github.com/koding/multiconfig"
	"os"
	// "strings"
	"time"
)

type (
	MainConfig struct {
		Network Network
		Redis   Redis
	}
	Network struct {
		Device      string `required:"true"`
		Timeout     int    `default:"2000"`
		Snaplen     int    `default:"1500"`
		Promiscuous bool   `default:"true"`
		UseZeroCopy bool   `default:"true"`
	}
	Redis struct {
		Host string `required:"true"`
		Port int    `required:"true"`
	}
)

var Config *redsnif.SniffConfig

func initConfig(configFile string) error {
	m := multiconfig.NewWithPath(configFile)
	mcfg := new(MainConfig)
	m.MustLoad(mcfg)

	Config = &redsnif.SniffConfig{}
	Config.Device = mcfg.Network.Device
	Config.Snaplen = int32(mcfg.Network.Snaplen)
	Config.Timeout = time.Duration(time.Millisecond * time.Duration(mcfg.Network.Timeout))
	Config.Promiscuous = mcfg.Network.Promiscuous
	Config.UseZeroCopy = mcfg.Network.UseZeroCopy
	Config.Host = mcfg.Redis.Host
	Config.Port = mcfg.Redis.Port

	return nil
}

func main() {
	configFile := "config.toml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	if err := initConfig(configFile); err != nil {
		panic(err)
	}

	logFile := "./log_hub.log"
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		panic(err)
	}

	hubcfg := &datahub.LogHubConfig{
		Output: f,
		Format: &logrus.JSONFormatter{},
	}
	lh := datahub.NewLogHubber(Config, hubcfg)
	if err := lh.Run(); err != nil {
		panic(err)
	}

	/*
		c := make(chan *redsnif.PacketInfo)
		if err := redsnif.PacketSniff(Config, c); err != nil {
			panic(err)
		}
		for {
			info := <-c
			payload := string(info.Payload)
			payload = strings.Replace(payload, "\r", "\\r", -1)
			payload = strings.Replace(payload, "\n", "\\n", -1)
			fmt.Printf("src %s:%d dst %s:%d payload %s seq %d sessionid %s ",
				info.SrcIP, info.SrcPort, info.DstIP, info.DstPort, payload,
				info.Seq, hex.EncodeToString(info.SessionID))
			rd, err := info.GetRespData()
			if err != nil {
				panic(err)
			}
			cmd, err := rd.GetCommand()
			if err == nil {
				fmt.Printf("cmd: %v\n", cmd)
			} else if rd.IsString() {
				fmt.Printf("type: %s string: %v\n", rd.MsgType(), rd.Msg.Status)
			} else if rd.IsInteger() {
				fmt.Printf("type: %s integer: %v\n", rd.MsgType(), rd.Msg.Integer)
			} else if rd.IsError() {
				fmt.Printf("type: %s error: %v\n", rd.MsgType(), rd.Msg.Error)
			} else {
				fmt.Printf("type: %s bytes: %s\n", rd.MsgType(), rd.Msg.Bytes)
			}
		}
	*/
}
