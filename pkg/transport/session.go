package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/zamasskin/dropdpi/pkg/protocol"
)

// Session represents a logical stream that can be split over multiple physical connections.
type Session struct {
	ID      uint64
	Key     []byte
	conns   []net.Conn
	mu      sync.Mutex
	sendSeq uint64
	connIdx int

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
		readCh:    make(chan []byte, 1000), // Increased buffer size
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

	// Split into chunks (smaller chunks to avoid blocking/fragmentation)
	chunkSize := 512 // Reduced from 1024 to 512
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

		// Send (Redundant: Send to 2 random connections to bypass packet loss/blocking)
		// Pick connections
		connsCount := len(s.conns)
		if connsCount == 0 {
			return sent, io.ErrClosedPipe
		}

		// Determine how many connections to use (Redundancy factor)
		// 2 is a good balance between reliability and overhead.
		redundancy := 2
		if connsCount < redundancy {
			redundancy = connsCount
		}

		// Random shuffle indices to pick distinct connections
		perm := rand.Perm(connsCount)

		successCount := 0
		// Try ALL connections until we satisfy redundancy or run out of options
		for _, connIdx := range perm {
			if successCount >= redundancy {
				break
			}

			conn := s.conns[connIdx]

			// Set write deadline to prevent blocking on a single stalled connection
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))

			_, err := conn.Write(frame)

			// Reset deadline
			conn.SetWriteDeadline(time.Time{})

			if err == nil {
				successCount++
				fmt.Printf("Sent frame Seq %d on conn %d (Redundant)\n", pkt.Seq, connIdx)
			} else {
				fmt.Printf("Failed to send frame Seq %d on conn %d: %v\n", pkt.Seq, connIdx, err)
			}
		}

		if successCount == 0 {
			// All connections failed
			fmt.Println("All connections failed to write")
			return sent, io.ErrClosedPipe
		}

		sent = end
	}

	return sent, nil
}

func (s *Session) Read(p []byte) (n int, err error) {
	s.mu.Lock()
	if len(s.leftover) > 0 {
		n = copy(p, s.leftover)
		s.leftover = s.leftover[n:]
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()

	select {
	case data, ok := <-s.readCh:
		if !ok {
			return 0, io.EOF
		}
		if len(data) > len(p) {
			n = copy(p, data)
			s.mu.Lock()
			s.leftover = data[n:]
			s.mu.Unlock()
			return n, nil
		}
		n = copy(p, data)
		return n, nil
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
		// Set deadline for every read to detect stalled connections
		// Increased to 1 hour to prevent killing active downloads where client is silent
		conn.SetReadDeadline(time.Now().Add(1 * time.Hour))

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

	fmt.Printf("S%d: In Seq %d (Want %d) Cmd %d BufSize %d\n", s.ID, pkt.Seq, s.recvSeq, pkt.Cmd, len(s.buffer))

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
