package rsniffer

import (
	"crypto/md5"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xiam/resp"
	"net"
	"strings"
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

type PacketInfo struct {
	Seq       int
	SessionID []byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   layers.TCPPort
	DstPort   layers.TCPPort
	Payload   []byte
	IsReq     bool
	err       error
}

type Session struct {
	ID      []byte
	counter int
	created int64
}

type SessionPool struct {
	sessions map[string]*Session
}

func NewSessionPool() *SessionPool {
	return &SessionPool{
		sessions: map[string]*Session{},
	}
}

func (sp *SessionPool) GetSession(packet *PacketInfo, cfg *SniffConfig) *Session {
	key, _ := TCPIdentify(packet.SrcIP, packet.DstIP, packet.SrcPort, packet.DstPort, cfg.Host, cfg.Port)
	if _, ok := sp.sessions[key]; !ok {
		now := time.Now().Unix()
		h := md5.New()
		idstr := fmt.Sprintf("%s-%d", key, now)
		h.Write([]byte(idstr))
		sp.sessions[key] = &Session{
			ID:      h.Sum(nil),
			counter: 0,
			created: time.Now().Unix(),
		}
	}
	session := sp.sessions[key]
	session.counter++
	return session
}

func (sp *SessionPool) RemoveSession(key string) {
	delete(sp.sessions, key)
}

func PacketProcess(packet gopacket.Packet, sp *SessionPool, cfg *SniffConfig) *PacketInfo {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var SrcIP, DstIP net.IP
	var SrcPort, DstPort layers.TCPPort
	if tcpLayer != nil && ipLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		ip, _ := ipLayer.(*layers.IPv4)
		SrcIP, DstIP = ip.SrcIP, ip.DstIP
		SrcPort, DstPort = tcp.SrcPort, tcp.DstPort
		if tcp.FIN {
			sessionKey, _ := TCPIdentify(SrcIP, DstIP, SrcPort, DstPort, cfg.Host, cfg.Port)
			sp.RemoveSession(sessionKey)
			return nil
		}
	}

	// Check application Layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		pinfo := &PacketInfo{
			Payload: applicationLayer.Payload(),
		}
		pinfo.SrcIP = SrcIP
		pinfo.DstIP = DstIP
		pinfo.SrcPort = SrcPort
		pinfo.DstPort = DstPort
		// Check for errors
		if err := packet.ErrorLayer(); err != nil {
			pinfo.err = err.Error()
		}
		session := sp.GetSession(pinfo, cfg)
		pinfo.Seq = session.counter
		pinfo.SessionID = session.ID
		pinfo.IsReq = (pinfo.DstIP.String() == cfg.Host) &&
			(int(pinfo.DstPort) == cfg.Port)
		return pinfo
	}
	return nil
}

func (pinfo *PacketInfo) GetRespData() (*RespData, error) {
	rd := &RespData{
		Msg:       &resp.Message{},
		RawPacket: pinfo,
	}
	if err := resp.Unmarshal(pinfo.Payload, rd.Msg); err != nil {
		return nil, err
	}
	return rd, nil
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

func RespDataAnalyze(lastRespD, currRespD *RespData, config *AnalyzeConfig) map[string]interface{} {
	cmd, _ := lastRespD.GetCommand()
	cmdName := strings.ToUpper(cmd.Name())
	cmdType, ok := RedisCmds[cmdName]
	if !ok {
		return nil
	}
	result := make(map[string]interface{})
	for _, saveCmdType := range config.SaveCmdTypes {
		if cmdType == saveCmdType {
			switch config.SaveDetail {
			case RecordRequest:
				result[AnalyzeRequest] = string(lastRespD.RawPacket.Payload)
			case RecordReply:
				result[AnalyzeReply] = string(currRespD.RawPacket.Payload)
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
	return result
}
