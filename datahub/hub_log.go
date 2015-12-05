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
	sessions map[string]*LogHubSession
}

type LogHubConfig struct {
	Output io.Writer
	Format logrus.Formatter
}

type LogHubSession struct {
	sid           string
	queuedRequest []*rsniffer.RespData
	queuedReply   []*rsniffer.RespData
}

func NewLogHubber(snifcfg *rsniffer.SniffConfig, hubcfg *LogHubConfig) *LogHubber {
	lh := &LogHubber{
		logger:  logrus.New(),
		snifcfg: snifcfg,
	}
	lh.logger.Out = hubcfg.Output
	lh.logger.Formatter = hubcfg.Format
	lh.sessions = map[string]*LogHubSession{}
	return lh
}

func (lh *LogHubber) Run() error {
	c := make(chan *rsniffer.RedSession)
	ec := make(chan error)
	go rsniffer.PacketSniff(lh.snifcfg, c, ec)
	for {
		select {
		case err := <-ec:
			return err
		case rs := <-c:
			lh.AnalyzePacketInfo(rs)
		}
	}
	return nil
}

func (lh *LogHubber) AnalyzePacketInfo(rs *rsniffer.RedSession) {
	request, reply, err := rs.GetRespData()
	if err != nil {
		log.Panicf("get respdata error: %v", err)
	}

	if _, ok := lh.sessions[string(rs.ID)]; !ok {
		lh.sessions[string(rs.ID)] = &LogHubSession{
			queuedRequest: make([]*rsniffer.RespData, 0),
			queuedReply:   make([]*rsniffer.RespData, 0),
		}
	}
	lhs := lh.sessions[string(rs.ID)]
	if request != nil && len(request) > 0 {
		lhs.queuedRequest = append(lhs.queuedRequest, request...)
	}
	if reply != nil && len(reply) > 0 {
		lhs.queuedReply = append(lhs.queuedReply, reply...)
	}

	// the length of queuedRequest should be always no smaller than the count of queuedReply
	replyCount := len(lhs.queuedReply)
	for i := 0; i < replyCount; i++ {
		var reqRD, repRD *rsniffer.RespData
		reqRD, lhs.queuedRequest = lhs.queuedRequest[0], lhs.queuedRequest[1:]
		repRD, lhs.queuedReply = lhs.queuedReply[0], lhs.queuedReply[1:]
		fields, err := rsniffer.RespDataAnalyze(reqRD, repRD, lh.snifcfg.AzConfig)
		if fields != nil {
			lh.logger.WithFields(fields).Info("log_hub basic")
		}
		if err != nil {
			lh.logger.Errorf("log_hub basic error: %v", err)
		}
	}
}
