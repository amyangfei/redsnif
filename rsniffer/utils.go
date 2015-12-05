package rsniffer

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"net"
)

type TCPMeta struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
}

func (tm *TCPMeta) FromSrcToDst(dstHost string, dstPort int) bool {
	return tm.DstIP.String() == dstHost && int(tm.DstPort) == dstPort
}

// TCPIdentify returns an identification for a TCP session, and data direction.
// As TCP is full-duplex we treat the in and out TCP traffic in a same session
func TCPIdentify(tm *TCPMeta, Host string, Port int) string {
	if tm.FromSrcToDst(Host, Port) {
		return fmt.Sprintf("%s:%d-%s:%d", tm.SrcIP, tm.SrcPort, tm.DstIP, tm.DstPort)
	} else {
		return fmt.Sprintf("%s:%d-%s:%d", tm.DstIP, tm.DstPort, tm.SrcIP, tm.SrcPort)
	}
}
