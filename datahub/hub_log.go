package datahub

import (
	"github.com/Sirupsen/logrus"
	"github.com/amyangfei/redsnif/rsniffer"
	"io"
	"log"
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
			fields := rsniffer.KeyHitAnalyze(session.lastResp, respData)
			if fields != nil {
				lh.logger.WithFields(fields).Info("log_hub basic")
			}
		}
		session.lastPacket = pinfo
		session.lastResp = respData
	}
}
