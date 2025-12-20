package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	CmdData    byte = 0x01
	CmdConnect byte = 0x02
	CmdClose   byte = 0x03
)

// Packet represents a decrypted message.
type Packet struct {
	SessionID uint64
	Seq       uint64
	Cmd       byte
	Payload   []byte
}

// Serialize converts the packet into bytes for encryption.
// Format: [SessionID(8)][Seq(8)][Cmd(1)][Payload(...)]
func (p *Packet) Serialize() []byte {
	buf := make([]byte, 8+8+1+len(p.Payload))
	binary.BigEndian.PutUint64(buf[0:8], p.SessionID)
	binary.BigEndian.PutUint64(buf[8:16], p.Seq)
	buf[16] = p.Cmd
	copy(buf[17:], p.Payload)
	return buf
}

// Deserialize parses the decrypted bytes into a Packet.
func Deserialize(data []byte) (*Packet, error) {
	if len(data) < 17 {
		return nil, errors.New("data too short for packet")
	}
	p := &Packet{}
	p.SessionID = binary.BigEndian.Uint64(data[0:8])
	p.Seq = binary.BigEndian.Uint64(data[8:16])
	p.Cmd = data[16]
	p.Payload = make([]byte, len(data)-17)
	copy(p.Payload, data[17:])
	return p, nil
}

// Frame adds the length prefix to the data (which should be the Encrypted blob).
// Format: [Length(4)][Data]
func Frame(data []byte) []byte {
	l := uint32(len(data))
	buf := make([]byte, 4+l)
	binary.BigEndian.PutUint32(buf[0:4], l)
	copy(buf[4:], data)
	return buf
}
