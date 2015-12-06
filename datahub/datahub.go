package datahub

import (
	"fmt"
	"github.com/amyangfei/redsnif/rsniffer"
)

const (
	HUB_ZMQ_PUBLISHER = iota + 1
	HUB_LOG_RECORDER
)

type DataHub interface {
	Run() error
}

type HubConfig struct {
	HubType    int
	Subscriber interface{}
}

type AnalyzeResultHandler func(map[string]interface{}, error)

type BaseHub struct {
	snifcfg  *rsniffer.SniffConfig
	sessions map[string]*HubSession
}

type HubSession struct {
	sid           string
	queuedRequest []*rsniffer.RespData
	queuedReply   []*rsniffer.RespData
}

func NewBaseHub(snifcfg *rsniffer.SniffConfig) *BaseHub {
	return &BaseHub{
		snifcfg:  snifcfg,
		sessions: map[string]*HubSession{},
	}
}

func (hub *BaseHub) AnalyzePacketInfo(rs *rsniffer.RedSession, handler AnalyzeResultHandler) {
	request, reply, err := rs.GetRespData()
	if err != nil {
		handler(nil, fmt.Errorf("get respdata error: %v", err))
		return
	}

	if _, ok := hub.sessions[string(rs.ID)]; !ok {
		hub.sessions[string(rs.ID)] = &HubSession{
			queuedRequest: make([]*rsniffer.RespData, 0),
			queuedReply:   make([]*rsniffer.RespData, 0),
		}
	}
	hs := hub.sessions[string(rs.ID)]
	if request != nil && len(request) > 0 {
		hs.queuedRequest = append(hs.queuedRequest, request...)
	}
	if reply != nil && len(reply) > 0 {
		hs.queuedReply = append(hs.queuedReply, reply...)
	}

	// the length of queuedRequest should be always no smaller than the count of queuedReply
	replyCount := len(hs.queuedReply)
	for i := 0; i < replyCount; i++ {
		var reqRD, replyRD *rsniffer.RespData
		reqRD, hs.queuedRequest = hs.queuedRequest[0], hs.queuedRequest[1:]
		replyRD, hs.queuedReply = hs.queuedReply[0], hs.queuedReply[1:]
		fields, err := rsniffer.RespDataAnalyze(reqRD, replyRD, hub.snifcfg.AzConfig)
		handler(fields, err)
	}
}
