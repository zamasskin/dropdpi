package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/zamasskin/dropdpi/pkg/config"
	"github.com/zamasskin/dropdpi/pkg/protocol"
	"github.com/zamasskin/dropdpi/pkg/transport"
)

var (
	serverAddr string
	serverKey  []byte
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	setupMode := flag.Bool("setup", false, "run interactive setup wizard")
	flag.Parse()

	if *setupMode {
		runSetup(*configPath)
		return
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override with positional argument if provided
	if flag.NArg() > 0 {
		cfg.ServerAddress = flag.Arg(0)
		log.Printf("Using Server Address from argument: %s", cfg.ServerAddress)
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

func runSetup(path string) {
	fmt.Println("=== DropDPI Client Setup ===")
	cfg := &config.Config{
		ServerListen: ":8443", // Defaults
		ClientListen: "127.0.0.1:1080",
		Key:          "0123456789abcdef0123456789abcdef",
	}

	fmt.Print("Enter Server Address (e.g. 1.2.3.4:8443 or 1.2.3.4:443,1.2.3.4:80): ")
	fmt.Scanln(&cfg.ServerAddress)

	if cfg.ServerAddress == "" {
		fmt.Println("Error: Server Address is required.")
		return
	}

	fmt.Printf("Enter Local Port (default 127.0.0.1:1080): ")
	var local string
	fmt.Scanln(&local)
	if local != "" {
		cfg.ClientListen = local
	}

	fmt.Printf("Enter Encryption Key (32 chars, press Enter for default): ")
	var key string
	fmt.Scanln(&key)
	if key != "" {
		cfg.Key = key
	}

	if err := cfg.Save(path); err != nil {
		fmt.Printf("Error saving config: %v\n", err)
		return
	}

	fmt.Printf("Configuration saved to %s\n", path)
	fmt.Println("You can now run the client normally.")
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

	// Parse server addresses (support comma-separated list)
	serverAddrs := strings.Split(serverAddr, ",")
	for i := range serverAddrs {
		serverAddrs[i] = strings.TrimSpace(serverAddrs[i])
	}

	for i := 0; i < numStreams; i++ {
		// Pick a random address from the list to distribute connections
		addr := serverAddrs[rand.Intn(len(serverAddrs))]

		c, err := net.Dial("tcp", addr)
		if err != nil {
			log.Printf("Failed to dial server %s: %v", addr, err)
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
