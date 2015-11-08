package rsniffer

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"net"
)

// TCPIdentify returns an identification for a TCP session, and data direction.
// Direction true means the traffic is from local(Host) to remote.
// As TCP is full-duplex we treat the in and out TCP traffic in a same session
func TCPIdentify(SrcIp, DstIp net.IP, SrcPort, DstPort layers.TCPPort, Host string, Port int) (string, bool) {
	if SrcIp.String() == Host && int(SrcPort) == Port {
		return fmt.Sprintf("%s:%d-%s:%d", SrcIp, SrcPort, DstIp, DstPort), true
	} else {
		return fmt.Sprintf("%s:%d-%s:%d", DstIp, DstPort, SrcIp, SrcPort), false
	}
}
