package datahub

import (
	"github.com/Sirupsen/logrus"
	"github.com/amyangfei/redsnif/rsniffer"
	"io"
	"log"
	"strings"
)

type LogHubber struct {
	logger   *logrus.Logger
	snifcfg  *rsniffer.SniffConfig
	sessions map[string]*RedisSession
}

type LogHubConfig struct {
	Output io.Writer
	Format logrus.Formatter
}

type RedisSession struct {
	sid        string
	lastPacket *rsniffer.PacketInfo
	lastResp   *rsniffer.RespData
}

func NewLogHubber(snifcfg *rsniffer.SniffConfig, hubcfg *LogHubConfig) *LogHubber {
	lh := &LogHubber{
		logger:  logrus.New(),
		snifcfg: snifcfg,
	}
	lh.logger.Out = hubcfg.Output
	lh.logger.Formatter = hubcfg.Format
	lh.sessions = map[string]*RedisSession{}
	return lh
}

func (lh *LogHubber) Run() error {
	c := make(chan *rsniffer.PacketInfo)
	ec := make(chan error)
	go rsniffer.PacketSniff(lh.snifcfg, c, ec)
	for {
		select {
		case err := <-ec:
			return err
		case info := <-c:
			lh.AnalyzePacketInfo(info)
		}
	}
	return nil
}

func (lh *LogHubber) AnalyzePacketInfo(pinfo *rsniffer.PacketInfo) {
	respData, err := pinfo.GetRespData()
	if err != nil {
		log.Panicf("get respdata error: %v", err)
	}

	if session, ok := lh.sessions[string(pinfo.SessionID)]; !ok {
		lh.sessions[string(pinfo.SessionID)] = &RedisSession{
			sid:        string(pinfo.SessionID),
			lastPacket: pinfo,
			lastResp:   respData,
		}
	} else {
		// last packet contains redis command
		if session.lastPacket.IsReq && session.lastResp.IsArray() {
			cmd, _ := session.lastResp.GetCommand()
			cmdName := strings.ToUpper(cmd.Name())
			params := make([]map[string]interface{}, 0)
			// last command is get
			if cmdName == "GET" {
				key := ""
				if len(cmd.Args) > 1 {
					key = cmd.Args[1]
				}
				var status int
				if respData.IsError() {
					status = rsniffer.KeyError
				} else if len(respData.Msg.Bytes) == 0 {
					status = rsniffer.KeyMiss
				} else {
					status = rsniffer.KeyHit
				}
				params = append(params, map[string]interface{}{
					"key":    key,
					"status": status,
				})
			} else if cmdName == "MGET" {
				if respData.IsError() {
					params = append(params, map[string]interface{}{
						"key":    0,
						"status": rsniffer.KeyError,
					})
				} else {
					for idx, key := range cmd.Args[1:] {
						var status int
						if len(respData.Msg.Array[idx].Bytes) == 0 {
							status = rsniffer.KeyMiss
						} else {
							status = rsniffer.KeyHit
						}
						params = append(params, map[string]interface{}{
							"key":    key,
							"status": status,
						})
					}
				}
			}
			lh.logger.WithFields(logrus.Fields{
				"cmd":    cmdName,
				"params": params,
			}).Info("log_hub basic")
		}
		session.lastPacket = pinfo
		session.lastResp = respData
	}
}
