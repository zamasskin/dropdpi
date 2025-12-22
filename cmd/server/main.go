package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zamasskin/dropdpi/pkg/config"
	"github.com/zamasskin/dropdpi/pkg/protocol"
	"github.com/zamasskin/dropdpi/pkg/transport"
)

var (
	// Loaded from config
	serverKey    []byte
	fakePagePath string
	sessions     = make(map[uint64]*transport.Session)
	mu           sync.Mutex
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	serverKey = []byte(cfg.Key)
	fakePagePath = cfg.FakePage

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
	// 1. Peek first 5 bytes to check for HTTP
	header := make([]byte, 5)
	n, err := io.ReadFull(conn, header)
	if err != nil {
		conn.Close()
		return
	}

	// 2. Check if HTTP
	if isHTTP(header) {
		serveFakePage(conn)
		return
	}

	// 3. If not HTTP, assume it's DropDPI protocol.
	// We need to pass the FULL stream (header + rest) to the protocol handler.
	// Since we already read 'header', we wrap the conn.
	bufferedConn := &BufferedConn{
		Conn:   conn,
		Reader: io.MultiReader(bytes.NewReader(header[:n]), conn),
	}

	handleDropDPI(bufferedConn)
}

func isHTTP(data []byte) bool {
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELE", "OPTI", "CONN"}
	s := string(data)
	for _, m := range methods {
		if strings.HasPrefix(s, m) {
			return true
		}
	}
	return false
}

func serveFakePage(conn net.Conn) {
	defer conn.Close()

	// Default Nginx-like page
	content := []byte(`<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`)

	if fakePagePath != "" {
		fileContent, err := os.ReadFile(fakePagePath)
		if err == nil {
			content = fileContent
		} else {
			log.Printf("Failed to read fake page: %v", err)
		}
	}

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Connection: close\r\n" +
		"\r\n"

	conn.Write([]byte(response))
	conn.Write(content)
}

// BufferedConn wraps a net.Conn and overrides Read to read from a specific reader first
type BufferedConn struct {
	net.Conn
	Reader io.Reader
}

func (b *BufferedConn) Read(p []byte) (n int, err error) {
	return b.Reader.Read(p)
}

func handleDropDPI(conn net.Conn) {
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
