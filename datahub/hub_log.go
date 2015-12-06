package datahub

import (
	"github.com/Sirupsen/logrus"
	"github.com/amyangfei/redsnif/rsniffer"
	"io"
)

type LogHubber struct {
	logger *logrus.Logger
	hub    *BaseHub
}

type LogHubConfig struct {
	Output io.Writer
	Format logrus.Formatter
}

func NewLogHubber(snifcfg *rsniffer.SniffConfig, hubcfg *LogHubConfig) *LogHubber {
	lh := &LogHubber{
		logger: logrus.New(),
		hub:    NewBaseHub(snifcfg),
	}
	lh.logger.Out = hubcfg.Output
	lh.logger.Formatter = hubcfg.Format
	return lh
}

func (lh *LogHubber) Run() error {
	c := make(chan *rsniffer.RedSession)
	ec := make(chan error)
	go rsniffer.PacketSniff(lh.hub.snifcfg, c, ec)
	for {
		select {
		case err := <-ec:
			// ignore redis session close error
			if err != rsniffer.RedSessionCloseErr {
				return err
			}
		case rs := <-c:
			lh.AnalyzePacketInfoWrapper(rs)
		}
	}
	return nil
}

func (lh *LogHubber) AnalyzePacketInfoWrapper(rs *rsniffer.RedSession) {
	lh.hub.AnalyzePacketInfo(rs, func(fields map[string]interface{}, err error) {
		if fields != nil {
			lh.logger.WithFields(fields).Info("log_hub basic")
		}
		if err != nil {
			lh.logger.Errorf("log_hub basic error: %v", err)
		}
	})
}
