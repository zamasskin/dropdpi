package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"

	"gitlab.tiande.tech/AlexeyZamasskin/dropdpi/pkg/config"
	"gitlab.tiande.tech/AlexeyZamasskin/dropdpi/pkg/protocol"
	"gitlab.tiande.tech/AlexeyZamasskin/dropdpi/pkg/transport"
)

var (
	serverAddr string
	serverKey  []byte
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	serverAddr = cfg.ServerAddress
	serverKey = []byte(cfg.Key)

	rand.Seed(time.Now().UnixNano())
	listener, err := net.Listen("tcp", cfg.ClientListen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 Client listening on %s", cfg.ClientListen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleSocks5(conn)
	}
}

func handleSocks5(conn net.Conn) {
	defer conn.Close()

	// 1. Auth Negotiation
	buf := make([]byte, 256)
	// Read Version and NMethods
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return // Only SOCKS5
	}
	nMethods := int(buf[1])
	// Read Methods
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}

	// Respond: No Auth
	conn.Write([]byte{0x05, 0x00})

	// 2. Request
	// [VER][CMD][RSV][ATYP][DST.ADDR][DST.PORT]
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	cmd := buf[1]
	if cmd != 0x01 { // CONNECT
		// We only support CONNECT
		return
	}

	addrType := buf[3]
	var host string
	switch addrType {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return
		}
		host = string(buf[:domainLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}

	// Port
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	log.Printf("Connecting to %s via Tunnel", target)

	// 3. Connect to Server (Create Session)
	sessionID := rand.Uint64()

	// Open N connections (Multiplexing)
	numStreams := 3
	conns := make([]net.Conn, 0, numStreams)
	for i := 0; i < numStreams; i++ {
		c, err := net.Dial("tcp", serverAddr)
		if err != nil {
			log.Println("Failed to dial server:", err)
			continue
		}
		conns = append(conns, c)
	}

	if len(conns) == 0 {
		log.Println("No connections to server")
		return
	}

	session := transport.NewSession(sessionID, serverKey, conns)
	defer session.Close()

	// Send Connect Command
	err := session.SendCommand(protocol.CmdConnect, []byte(target))
	if err != nil {
		log.Println("Failed to send connect command:", err)
		return
	}

	// 4. Respond Success to Browser
	// We assume success for now (optimistic) because we don't wait for server Ack in this simple protocol
	// Reply: [VER][REP][RSV][ATYP][BND.ADDR][BND.PORT]
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// 5. Pipe
	// Browser -> Client -> Session
	go func() {
		io.Copy(session, conn)
		// Usually we should close write here, but let's just close session
	}()

	// Session -> Client -> Browser
	io.Copy(conn, session)
}
