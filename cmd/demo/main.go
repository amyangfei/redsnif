package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/amyangfei/redsnif/datahub"
	redsnif "github.com/amyangfei/redsnif/rsniffer"
	"github.com/koding/multiconfig"
	"os"
	"time"
)

type (
	MainConfig struct {
		Network Network
		Redis   Redis
		Analyze Analyze
	}
	Network struct {
		Device      string `required:"true"`
		Timeout     int    `default:"2000"`
		Snaplen     int    `default:"1500"`
		Promiscuous bool   `default:"true"`
		UseZeroCopy bool   `default:"true"`
	}
	Redis struct {
		Host       string `required:"true"`
		Port       int    `required:"true"`
		MaxBufSize int    `default:"3000"`
	}
	Analyze struct {
		ReadHitAnalyze bool  `default:"true"`
		SaveCmdTypes   []int `required:"true"`
		SaveDetail     int   `required:"true"`
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
	Config.MaxBufSize = mcfg.Redis.MaxBufSize
	Config.AzConfig = &redsnif.AnalyzeConfig{
		ReadHitAnalyze: mcfg.Analyze.ReadHitAnalyze,
		SaveCmdTypes:   mcfg.Analyze.SaveCmdTypes,
		SaveDetail:     mcfg.Analyze.SaveDetail,
	}

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
}
