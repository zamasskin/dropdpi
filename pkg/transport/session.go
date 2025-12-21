package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"

	"github.com/zamasskin/dropdpi/pkg/protocol"
)

// Session represents a logical stream that can be split over multiple physical connections.
type Session struct {
	ID      uint64
	Key     []byte
	conns   []net.Conn
	mu      sync.Mutex
	sendSeq uint64

	// Reassembly
	recvSeq   uint64
	buffer    map[uint64]*protocol.Packet
	readCh    chan []byte // Ordered data ready to be read
	ConnectCh chan string
	closeCh   chan struct{}
	closed    bool

	// Read State
	leftover []byte
}

func NewSession(id uint64, key []byte, conns []net.Conn) *Session {
	s := &Session{
		ID:        id,
		Key:       key,
		conns:     make([]net.Conn, 0),
		buffer:    make(map[uint64]*protocol.Packet),
		readCh:    make(chan []byte, 100), // Buffer some chunks
		ConnectCh: make(chan string, 1),
		closeCh:   make(chan struct{}),
	}

	// Start reading from all connections
	for _, c := range conns {
		s.AddConnection(c)
	}

	return s
}

func (s *Session) AddConnection(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns = append(s.conns, conn)
	go s.readLoop(conn)
}

func (s *Session) InjectPacket(pkt *protocol.Packet) {
	s.handlePacket(pkt)
}

func (s *Session) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("Session %d: Write %d bytes\n", s.ID, len(p))

	if s.closed {
		return 0, io.ErrClosedPipe
	}

	// Split into chunks (e.g., 1024 bytes payload)
	chunkSize := 1024
	total := len(p)
	sent := 0

	for sent < total {
		end := sent + chunkSize
		if end > total {
			end = total
		}

		chunk := p[sent:end]

		// Create packet
		pkt := &protocol.Packet{
			SessionID: s.ID,
			Seq:       s.sendSeq,
			Cmd:       protocol.CmdData,
			Payload:   chunk, // This copies the slice header, but we serialize immediately so it's fine
		}
		s.sendSeq++

		// Serialize and Encrypt
		plaintext := pkt.Serialize()
		ciphertext, err := protocol.EncryptAESGCM(s.Key, plaintext)
		if err != nil {
			return sent, err
		}

		// Frame it
		frame := protocol.Frame(ciphertext)

		// Pick a connection (Round Robin or Random)
		// Simple Random for now to demonstrate "multiple streams" usage without complex state
		connIdx := rand.Intn(len(s.conns))
		conn := s.conns[connIdx]

		// Send
		_, err = conn.Write(frame)
		if err != nil {
			fmt.Println("Write to conn error:", err)
			// If one fails, we should probably remove it and try another,
			// but for MVP let's just return error
			return sent, err
		}
		fmt.Printf("Sent frame of len %d on conn %d\n", len(frame), connIdx)

		sent = end
	}

	return sent, nil
}

func (s *Session) Read(p []byte) (n int, err error) {
	// This is a simple implementation that reads one chunk at a time from the channel.
	// It doesn't handle partial reads well (if p is smaller than the chunk).
	// Ideally we need a buffer here too.
	// But let's assume p is large enough for now or use a persistent buffer.

	// For simplicity, let's just grab from the channel.
	// NOTE: This implementation assumes p is large enough to hold a chunk.

	select {
	case data, ok := <-s.readCh:
		if !ok {
			return 0, io.EOF
		}
		copy(p, data)
		return len(data), nil
	case <-s.closeCh:
		return 0, io.EOF
	}
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closeCh)
	// We don't close the conns here immediately because they might be shared or we might want to send a close packet.
	// But for this specific design where Session OWNS the conns:
	for _, c := range s.conns {
		c.Close()
	}
	return nil
}

func (s *Session) readLoop(conn net.Conn) {
	defer conn.Close()

	fmt.Println("Starting readLoop for connection")

	for {
		// Read Length
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			fmt.Println("Read Length error:", err)
			return // Connection dead
		}
		length := binary.BigEndian.Uint32(lenBuf)

		fmt.Printf("Reading packet length: %d\n", length)

		// Read Encrypted Data
		data := make([]byte, length)
		if _, err := io.ReadFull(conn, data); err != nil {
			fmt.Println("Read Data error:", err)
			return
		}

		// Decrypt
		plaintext, err := protocol.DecryptAESGCM(s.Key, data)
		if err != nil {
			fmt.Println("Decrypt error:", err)
			continue
		}

		// Deserialize
		pkt, err := protocol.Deserialize(plaintext)
		if err != nil {
			fmt.Println("Deserialize error:", err)
			continue
		}

		// We only care about our session
		if pkt.SessionID != s.ID {
			continue
		}

		s.handlePacket(pkt)
	}
}

func (s *Session) SendCommand(cmd byte, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return io.ErrClosedPipe
	}

	pkt := &protocol.Packet{
		SessionID: s.ID,
		Seq:       s.sendSeq,
		Cmd:       cmd,
		Payload:   payload,
	}
	s.sendSeq++

	// Serialize and Encrypt
	plaintext := pkt.Serialize()
	ciphertext, err := protocol.EncryptAESGCM(s.Key, plaintext)
	if err != nil {
		return err
	}

	frame := protocol.Frame(ciphertext)

	connIdx := rand.Intn(len(s.conns))
	conn := s.conns[connIdx]

	_, err = conn.Write(frame)
	return err
}

func (s *Session) handlePacket(pkt *protocol.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	// fmt.Printf("Session %d: Handle Packet Seq %d Cmd %d (RecvSeq %d)\n", s.ID, pkt.Seq, pkt.Cmd, s.recvSeq)

	if pkt.Seq < s.recvSeq {
		return // Duplicate or old
	}

	if pkt.Seq > s.recvSeq {
		// Buffer future packet
		// fmt.Printf("Session %d: Buffering Seq %d\n", s.ID, pkt.Seq)
		s.buffer[pkt.Seq] = pkt
		return
	}

	// pkt.Seq == s.recvSeq
	s.processOrderedPacket(pkt)
	s.recvSeq++

	// Process buffer
	for {
		nextPkt, ok := s.buffer[s.recvSeq]
		if !ok {
			break
		}
		delete(s.buffer, s.recvSeq)
		s.processOrderedPacket(nextPkt)
		s.recvSeq++
	}
}

func (s *Session) processOrderedPacket(pkt *protocol.Packet) {
	switch pkt.Cmd {
	case protocol.CmdClose:
		s.closed = true
		close(s.readCh)
		close(s.closeCh)
	case protocol.CmdConnect:
		select {
		case s.ConnectCh <- string(pkt.Payload):
		default:
		}
	case protocol.CmdData:
		s.readCh <- pkt.Payload
	}
}
