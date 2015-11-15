package main

import (
	"encoding/hex"
	"fmt"
	redsnif "github.com/amyangfei/redsnif/rsniffer"
	"github.com/koding/multiconfig"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type CacheOpRecord struct {
	hit  int64
	miss int64
	err  int64
}

func (cor *CacheOpRecord) Stat() string {
	total := cor.hit + cor.miss + cor.err
	hitrate := float64(cor.hit) / float64(total)
	missrate := float64(cor.miss) / float64(total)
	return fmt.Sprintf(
		"hitrate: %.3f missrate: %.3f total: %d", hitrate, missrate, total)
}

type RedisSession struct {
	sid        string
	record     *CacheOpRecord
	lastPacket *redsnif.PacketInfo
	lastResp   *redsnif.RespData
}

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
		Host       string   `required:"true"`
		Port       int      `required:"true"`
		KeyPattern []string `required:"true"`
	}
)

var Config *redsnif.SniffConfig
var MConfig *MainConfig

var GlobalRecord *CacheOpRecord
var Sessions map[string]*RedisSession

var quit = make(chan struct{})

// register signals handler
func initSignal() chan os.Signal {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM,
		syscall.SIGINT, syscall.SIGSTOP)
	return c
}

func handleSignal(c chan os.Signal) {
	// Block until a signal is received
	for {
		s := <-c
		switch s {
		case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGSTOP, syscall.SIGINT:
			close(quit)
			return
		case syscall.SIGHUP:
			// TODO reload
		default:
			return
		}
	}
}

func initConfig(configFile string) error {
	m := multiconfig.NewWithPath(configFile)
	MConfig = &MainConfig{}
	m.MustLoad(MConfig)

	Config = &redsnif.SniffConfig{}
	Config.Device = MConfig.Network.Device
	Config.Snaplen = int32(MConfig.Network.Snaplen)
	Config.Timeout = time.Duration(time.Millisecond * time.Duration(MConfig.Network.Timeout))
	Config.Promiscuous = MConfig.Network.Promiscuous
	Config.UseZeroCopy = MConfig.Network.UseZeroCopy
	Config.Host = MConfig.Redis.Host
	Config.Port = MConfig.Redis.Port

	return nil
}

func initService() error {
	GlobalRecord = &CacheOpRecord{}
	Sessions = map[string]*RedisSession{}
	return nil
}

func sniffer() {
	c := make(chan *redsnif.PacketInfo)
	go func() {
		if err := redsnif.PacketSniff(Config, c); err != nil {
			panic(err)
		}
	}()
	for {
		info := <-c
		respData, err := info.GetRespData()
		if err != nil {
			panic(err)
		}
		if session, ok := Sessions[string(info.SessionID)]; !ok {
			Sessions[string(info.SessionID)] = &RedisSession{
				sid:        string(info.SessionID),
				record:     &CacheOpRecord{hit: 0, miss: 0, err: 0},
				lastPacket: info,
				lastResp:   respData,
			}
		} else {
			// last packet contains redis command
			if session.lastResp.IsArray() {
				cmd, _ := session.lastResp.GetCommand()
				// last command is get
				if strings.ToUpper(cmd.Name()) == "GET" {
					if !respData.IsBulk() {
						session.record.err++
						GlobalRecord.err++
					} else if len(respData.Msg.Bytes) == 0 {
						session.record.miss++
						GlobalRecord.miss++
					} else {
						session.record.hit++
						GlobalRecord.hit++
					}
				}
			}
			session.lastPacket = info
			session.lastResp = respData
		}
	}
}

func reporter() {
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				fmt.Printf("global stat: %s\n", GlobalRecord.Stat())
				for sid, session := range Sessions {
					fmt.Printf("session: %s, stat: %s: \n",
						hex.EncodeToString([]byte(sid)), session.record.Stat())
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}

func main() {
	configFile := "config.toml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	if err := initConfig(configFile); err != nil {
		panic(err)
	}
	if err := initService(); err != nil {
		panic(err)
	}
	go sniffer()
	go reporter()

	signalChan := initSignal()
	handleSignal(signalChan)
}
