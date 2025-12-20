package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"gitlab.tiande.tech/AlexeyZamasskin/dropdpi/pkg/config"
	"gitlab.tiande.tech/AlexeyZamasskin/dropdpi/pkg/protocol"
	"gitlab.tiande.tech/AlexeyZamasskin/dropdpi/pkg/transport"
)

var (
	// Loaded from config
	serverKey []byte
	sessions  = make(map[uint64]*transport.Session)
	mu        sync.Mutex
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	serverKey = []byte(cfg.Key)

	listener, err := net.Listen("tcp", cfg.ServerListen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Server listening on %s", cfg.ServerListen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	// We need to peek at the first packet to get SessionID.
	// The protocol is: [Length][Encrypted]
	// Encrypted contains: [SessionID]...

	// Read Length
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		return
	}
	length := binary.BigEndian.Uint32(header)

	// Read Encrypted Payload
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(conn, encrypted); err != nil {
		conn.Close()
		return
	}

	// Decrypt to peek SessionID
	plaintext, err := protocol.DecryptAESGCM(serverKey, encrypted)
	if err != nil {
		log.Println("Decrypt error:", err)
		conn.Close()
		return
	}

	// Deserialize
	pkt, err := protocol.Deserialize(plaintext)
	if err != nil {
		log.Println("Packet error:", err)
		conn.Close()
		return
	}

	sessionID := pkt.SessionID

	mu.Lock()
	session, exists := sessions[sessionID]
	if !exists {
		log.Printf("New Session: %d", sessionID)
		session = transport.NewSession(sessionID, serverKey, nil)
		sessions[sessionID] = session
		go handleSession(session)
	}
	mu.Unlock()

	// Add connection to session
	session.AddConnection(conn)

	// IMPORTANT: We already read the first packet from 'conn'.
	// We must inject it into the session logic.
	session.InjectPacket(pkt)
}

func handleSession(session *transport.Session) {
	defer func() {
		mu.Lock()
		delete(sessions, session.ID)
		mu.Unlock()
		session.Close()
	}()

	// Wait for Connect command
	var targetAddr string
	select {
	case targetAddr = <-session.ConnectCh:
		log.Printf("Session %d connecting to %s", session.ID, targetAddr)
	case <-time.After(10 * time.Second):
		log.Printf("Session %d timed out waiting for Connect", session.ID)
		return
	}

	// Dial Target
	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		log.Printf("Failed to dial %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Start Pipe
	// Server -> Client (Read from Target, Write to Session)
	go func() {
		defer session.Close() // If target closes, close session
		// io.Copy(session, targetConn)
		if _, err := io.Copy(session, targetConn); err != nil {
			log.Printf("Copy Target->Session error: %v", err)
		} else {
			log.Println("Copy Target->Session finished")
		}
	}()

	// Client -> Server (Read from Session, Write to Target)
	// io.Copy(targetConn, session)
	if _, err := io.Copy(targetConn, session); err != nil {
		log.Printf("Copy Session->Target error: %v", err)
	} else {
		log.Println("Copy Session->Target finished")
	}
}
