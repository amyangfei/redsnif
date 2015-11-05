package rsniffer

import (
	"github.com/google/gopacket"
	"io"
)

type ZeroCopyPacketSource struct {
	source  gopacket.ZeroCopyPacketDataSource
	decoder gopacket.Decoder
	gopacket.DecodeOptions
	c chan gopacket.Packet
}

// NewZeroCopyPacketSource creates a packet data source.
func NewZeroCopyPacketSource(
	source gopacket.ZeroCopyPacketDataSource, decoder gopacket.Decoder) *ZeroCopyPacketSource {
	return &ZeroCopyPacketSource{
		source:  source,
		decoder: decoder,
	}
}

// NextPacket returns the next decoded packet from the ZeroCopyPacketSource.
// On error, it returns a nil packet and a non-nil error.
func (p *ZeroCopyPacketSource) NextPacket() (gopacket.Packet, error) {
	data, ci, err := p.source.ZeroCopyReadPacketData()
	if err != nil {
		return nil, err
	}
	packet := gopacket.NewPacket(data, p.decoder, p.DecodeOptions)
	m := packet.Metadata()
	m.CaptureInfo = ci
	m.Truncated = m.Truncated || ci.CaptureLength < ci.Length
	return packet, nil
}

// packetsToChannel reads in all packets from the packet source and sends them
// to the given channel.  When it receives an error, it ignores it.  When it
// receives an io.EOF, it closes the channel.
func (p *ZeroCopyPacketSource) packetsToChannel() {
	defer close(p.c)
	for {
		packet, err := p.NextPacket()
		if err == io.EOF {
			return
		} else if err == nil {
			p.c <- packet
		}
	}
}

// Packets returns a channel of packets, allowing easy iterating over
// packets.  Packets will be asynchronously read in from the underlying
// PacketDataSource and written to the returned channel.  If the underlying
// PacketDataSource returns an io.EOF error, the channel will be closed.
// If any other error is encountered, it is ignored.
func (p *ZeroCopyPacketSource) Packets() chan gopacket.Packet {
	if p.c == nil {
		p.c = make(chan gopacket.Packet, 1000)
		go p.packetsToChannel()
	}
	return p.c
}
