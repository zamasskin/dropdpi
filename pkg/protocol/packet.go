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
	Padding   []byte
	Payload   []byte
}

// Serialize converts the packet into bytes for encryption.
// Format: [SessionID(8)][Seq(8)][Cmd(1)][PaddingLen(2)][Padding(...)][Payload(...)]
func (p *Packet) Serialize() []byte {
	paddingLen := len(p.Padding)
	totalLen := 8 + 8 + 1 + 2 + paddingLen + len(p.Payload)
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint64(buf[0:8], p.SessionID)
	binary.BigEndian.PutUint64(buf[8:16], p.Seq)
	buf[16] = p.Cmd
	binary.BigEndian.PutUint16(buf[17:19], uint16(paddingLen))
	copy(buf[19:19+paddingLen], p.Padding)
	copy(buf[19+paddingLen:], p.Payload)
	return buf
}

// Deserialize parses the decrypted bytes into a Packet.
func Deserialize(data []byte) (*Packet, error) {
	if len(data) < 19 {
		return nil, errors.New("data too short for packet")
	}
	p := &Packet{}
	p.SessionID = binary.BigEndian.Uint64(data[0:8])
	p.Seq = binary.BigEndian.Uint64(data[8:16])
	p.Cmd = data[16]

	paddingLen := int(binary.BigEndian.Uint16(data[17:19]))
	if len(data) < 19+paddingLen {
		return nil, errors.New("data too short for padding")
	}

	// We don't strictly need to store the padding on read, but let's keep it for symmetry if needed
	// or just skip it. Let's store it to be safe.
	p.Padding = make([]byte, paddingLen)
	copy(p.Padding, data[19:19+paddingLen])

	p.Payload = make([]byte, len(data)-(19+paddingLen))
	copy(p.Payload, data[19+paddingLen:])
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
