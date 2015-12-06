package rsniffer

import (
	"crypto/md5"
	"fmt"
	"github.com/amyangfei/resp-go/resp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"strings"
	"sync"
	"time"
)

type AnalyzeConfig struct {
	ReadHitAnalyze bool  // whether analyze hit/miss of readreply command
	SaveCmdTypes   []int // command types that will be recorded
	SaveDetail     int   // record detail: cmd only, with params or with reply
}

var BasicAnalyzeConfig *AnalyzeConfig = &AnalyzeConfig{
	ReadHitAnalyze: true,
	SaveCmdTypes:   []int{RedisCmdRead},
	SaveDetail:     RecordParams,
}

type RedSession struct {
	ID      []byte
	Counter int
	Created int64
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
	RBuf    []byte // data buffer for request from client to redis
	WBuf    []byte // data buffer for reply from redis to client
	REnd    int    // the last process byte index of RBuf
	WEnd    int    // the last process byte index of WBuf
	mu      sync.Mutex
}

type RedSessionPool struct {
	sessions map[string]*RedSession
}

func NewRedSessionPool() *RedSessionPool {
	return &RedSessionPool{
		sessions: map[string]*RedSession{},
	}
}

func (sp *RedSessionPool) GetRedSession(tcpMeta *TCPMeta, cfg *SniffConfig) *RedSession {
	if tcpMeta == nil {
		return nil
	}
	key := TCPIdentify(tcpMeta, cfg.Host, cfg.Port)
	if _, ok := sp.sessions[key]; !ok {
		now := time.Now().Unix()
		h := md5.New()
		idstr := fmt.Sprintf("%s-%d", key, now)
		h.Write([]byte(idstr))
		sp.sessions[key] = &RedSession{
			ID:      h.Sum(nil),
			Counter: 0,
			Created: time.Now().Unix(),
			SrcIP:   tcpMeta.SrcIP,
			DstIP:   tcpMeta.DstIP,
			SrcPort: tcpMeta.SrcPort,
			DstPort: tcpMeta.DstPort,
			RBuf:    make([]byte, cfg.Snaplen*2),
			WBuf:    make([]byte, cfg.Snaplen*2),
			REnd:    0,
			WEnd:    0,
		}
	}
	session := sp.sessions[key]
	session.Counter++
	return session
}

func (sp *RedSessionPool) RemoveRedSession(key string) {
	delete(sp.sessions, key)
}

func PacketProcess(packet gopacket.Packet, sp *RedSessionPool, cfg *SniffConfig) (*RedSession, error) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var tcpMeta *TCPMeta = nil
	if tcpLayer != nil && ipLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		ip, _ := ipLayer.(*layers.IPv4)
		tcpMeta = &TCPMeta{
			SrcIP:   ip.SrcIP,
			DstIP:   ip.DstIP,
			SrcPort: tcp.SrcPort,
			DstPort: tcp.DstPort,
		}
		if tcp.FIN {
			sessionKey := TCPIdentify(tcpMeta, cfg.Host, cfg.Port)
			sp.RemoveRedSession(sessionKey)
			return nil, RedSessionCloseErr
		}
	}

	// Check application Layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		session := sp.GetRedSession(tcpMeta, cfg)
		fromCliToRedis := tcpMeta.FromSrcToDst(cfg.Host, cfg.Port)
		payload := applicationLayer.Payload()
		if fromCliToRedis {
			err := session.AppendRequestData(payload)
			if err != nil {
				return nil, err
			}
		} else {
			err := session.AppendReplyData(payload)
			if err != nil {
				return nil, err
			}
		}
		return session, nil
	}
	return nil, nil
}

func (rs *RedSession) AppendRequestData(payload []byte) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.REnd+len(payload) > len(rs.RBuf) {
		return fmt.Errorf("data %d exceed max RBuf size", rs.REnd+len(payload))
	}
	// TODO: no copy support?
	copy(rs.RBuf[rs.REnd:], payload)
	rs.REnd += len(payload)
	return nil
}

func (rs *RedSession) AppendReplyData(payload []byte) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.WEnd+len(payload) > len(rs.WBuf) {
		return fmt.Errorf("data %d exceed max WBuf size", rs.WEnd+len(payload))
	}
	// TODO: no copy support?
	copy(rs.WBuf[rs.WEnd:], payload)
	rs.WEnd += len(payload)
	return nil
}

func (rs *RedSession) GetRespData() (request, reply []*RespData, err error) {
	reqMsgs, pos, err := resp.Decode(rs.RBuf[0:rs.REnd])
	request = make([]*RespData, 0)
	for _, msg := range reqMsgs {
		request = append(request, &RespData{Msg: msg})
	}
	copy(rs.RBuf, rs.RBuf[pos:rs.REnd])
	rs.REnd = rs.REnd - pos

	replyMsgs, pos, err := resp.Decode(rs.WBuf[0:rs.WEnd])
	reply = make([]*RespData, 0)
	for _, msg := range replyMsgs {
		reply = append(reply, &RespData{Msg: msg})
	}
	copy(rs.WBuf, rs.RBuf[pos:rs.WEnd])
	rs.WEnd = rs.WEnd - pos

	return request, reply, nil
}

// cmd: a Command struct represents client request to redis
// cmdName: name of cmd
// currRespD: a RespData struct represents the reply from redis
func KeyHitAnalyze(cmd *Command, cmdName string, currRespD *RespData) []map[string]interface{} {
	stat := make([]map[string]interface{}, 0)
	// last command is get
	if cmdName == "GET" {
		key := ""
		if len(cmd.Args) > 1 {
			key = cmd.Args[1]
		}
		var status int
		if currRespD.IsError() {
			status = KeyError
		} else if len(currRespD.Msg.Bytes) == 0 {
			status = KeyMiss
		} else {
			status = KeyHit
		}
		stat = append(stat, map[string]interface{}{
			"key":    key,
			"status": status,
		})
	} else if cmdName == "MGET" {
		if currRespD.IsError() {
			stat = append(stat, map[string]interface{}{
				"key":    "",
				"status": KeyError,
			})
		} else {
			for idx, key := range cmd.Args[1:] {
				var status int
				if len(currRespD.Msg.Array[idx].Bytes) == 0 {
					status = KeyMiss
				} else {
					status = KeyHit
				}
				stat = append(stat, map[string]interface{}{
					"key":    key,
					"status": status,
				})
			}
		}
	}
	if len(stat) == 0 {
		return nil
	}
	return stat
}

func RespDataAnalyze(lastRespD, currRespD *RespData, config *AnalyzeConfig) (map[string]interface{}, error) {
	cmd, err := lastRespD.GetCommand()
	if err != nil {
		return nil, err
	}
	cmdName := strings.ToUpper(cmd.Name())
	cmdType, ok := RedisCmds[cmdName]
	if !ok {
		return nil, nil
	}
	result := make(map[string]interface{})
	for _, saveCmdType := range config.SaveCmdTypes {
		if cmdType == saveCmdType {
			switch config.SaveDetail {
			case RecordRequest:
				// ignore error
				raw, _ := lastRespD.RawPayload()
				result[AnalyzeRequest] = string(raw)
				fallthrough
			case RecordReply:
				// ignore error
				raw, _ := currRespD.RawPayload()
				result[AnalyzeReply] = string(raw)
				fallthrough
			case RecordParams:
				result[AnalyzeParams] = cmd.Args[1:]
				fallthrough
			case RecordCmdOnly:
				result[AnalyzeCmd] = cmdName
				result[AnalyzeCmdType] = cmdType
			}
			if config.ReadHitAnalyze && cmdType == RedisCmdRead {
				stat := KeyHitAnalyze(cmd, cmdName, currRespD)
				if stat != nil {
					result[AnalyzeStat] = stat
				}
			}
		}
	}
	return result, nil
}
