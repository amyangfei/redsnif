package rsniffer

import (
	"crypto/md5"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xiam/resp"
	"net"
	"time"
)

type PacketInfo struct {
	Seq       int
	SessionID []byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   layers.TCPPort
	DstPort   layers.TCPPort
	Payload   []byte
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
		return pinfo
	}
	return nil
}

func (pinfo *PacketInfo) GetRespData() (*RespData, error) {
	rd := &RespData{
		Msg: &resp.Message{},
	}
	if err := resp.Unmarshal(pinfo.Payload, rd.Msg); err != nil {
		return nil, err
	}
	return rd, nil
}
