package datahub

import (
	"fmt"
	"github.com/amyangfei/redsnif/rsniffer"
	"strings"
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
	s        *rsniffer.Sniffer
	sessions map[string]*HubSession
}

type HubSession struct {
	sid            string
	queuedRequest  []*rsniffer.RespData
	queuedReply    []*rsniffer.RespData
	flags          int // REDIS_MULTI | REDIS_PUBSUB ...
	multiQueuedReq []*rsniffer.RespData
}

func NewBaseHub(snifcfg *rsniffer.SniffConfig) *BaseHub {
	return &BaseHub{
		s:        rsniffer.NewSniffer(snifcfg),
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
			queuedRequest:  make([]*rsniffer.RespData, 0),
			queuedReply:    make([]*rsniffer.RespData, 0),
			multiQueuedReq: make([]*rsniffer.RespData, 0),
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
		if len(hs.queuedRequest) == 0 {
			//replyLen := replyCount - i
			//raw, _ := hs.queuedReply[0].RawPayload()
			//fmt.Printf("%d raw: %s rawstr: %s\n", replyLen, raw, string(raw))
			// fmt.Printf("rcounter: %d wcounter: %d rsize: %d wsize: %d\n", hub.s.RCounter, hub.s.WCounter, hub.s.RSize, hub.s.WSize)
			break
		}
		var reqRD, replyRD *rsniffer.RespData
		reqRD, hs.queuedRequest = hs.queuedRequest[0], hs.queuedRequest[1:]
		replyRD, hs.queuedReply = hs.queuedReply[0], hs.queuedReply[1:]

		// client request itself to redis with error
		cmd, err := reqRD.GetCommand()
		if err != nil {
			handler(nil, err)
			continue
		}
		// client request to redis with error
		if replyRD.IsError() {
			fields, err := rsniffer.RespErrorAnalyze(reqRD, replyRD, hub.s.Config.AzConfig)
			handler(fields, err)
			continue
		}
		// start a transaction
		cmdName := strings.ToUpper(cmd.Name())
		if cmdName == "MULTI" && replyRD.IsString() && replyRD.Msg.Status == "OK" {
			hs.multiQueuedReq = make([]*rsniffer.RespData, 0)
			hs.flags |= RedisMulti
			continue
		}
		// redis session is in transaction
		if hs.flags&RedisMulti > 0 {
			if cmdName == "DISCARD" {
				// discard a transaction
				handler(map[string]interface{}{rsniffer.AnalyzeMesg: "transaction discard"}, nil)
				hs.flags &= ^RedisMulti
				continue
			} else if cmdName == "EXEC" {
				// exec a transaction
				if !replyRD.IsArray() || len(replyRD.Msg.Array) != len(hs.multiQueuedReq) {
					hs.flags &= ^RedisMulti
					handler(nil, fmt.Errorf("multi result count doesn't match queued requests"))
					continue
				}
				for j := 0; j < len(hs.multiQueuedReq); j++ {
					tReq := hs.multiQueuedReq[j]
					tReply := &rsniffer.RespData{Msg: replyRD.Msg.Array[j]}
					fields, err := rsniffer.RespDataAnalyze(tReq, tReply, hub.s.Config.AzConfig)
					handler(fields, err)
				}
				hs.flags &= ^RedisMulti
				continue
			} else {
				// redis command queued
				hs.multiQueuedReq = append(hs.multiQueuedReq, reqRD)
				continue
			}
		}

		// normal request and reply
		fields, err := rsniffer.RespDataAnalyze(reqRD, replyRD, hub.s.Config.AzConfig)
		handler(fields, err)
	}
}
