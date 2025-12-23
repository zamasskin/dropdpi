package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all for now
		},
	}
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

	// Support multiple listen addresses (e.g. ":8443,:8080", ":8000-8005")
	addrs := parsePorts(cfg.ServerListen)
	var wg sync.WaitGroup
	var activeListeners int

	http.HandleFunc("/", serveFakeHTTP)
	http.HandleFunc("/ws", serveWS) // Secret path

	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}

		log.Printf("Server listening on %s (WSS/HTTPS)", addr)
		activeListeners++

		wg.Add(1)
		go func(listenAddr string) {
			defer wg.Done()

			// Try TLS first (if certs exist)
			err := http.ListenAndServeTLS(listenAddr, "server.crt", "server.key", nil)
			if err != nil {
				log.Printf("Failed to listen TLS on %s: %v. Fallback to HTTP.", listenAddr, err)
				err = http.ListenAndServe(listenAddr, nil)
				if err != nil {
					log.Printf("Failed to listen HTTP on %s: %v", listenAddr, err)
				}
			}
		}(addr)
	}

	if activeListeners == 0 {
		log.Fatal("No listeners started. Check your configuration and port availability.")
	}

	wg.Wait()
}

func serveWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}

	// Wrap WS in net.Conn adapter
	conn := transport.NewWebSocketConn(ws)
	handleDropDPI(conn)
}

func serveFakeHTTP(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "nginx/1.18.0")
	w.Write(content)
}

func parsePorts(input string) []string {
	var result []string
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for range (e.g. :8000-8005 or 8000-8005)
		if strings.Contains(part, "-") {
			// Find the last colon to separate host from port range
			lastColon := strings.LastIndex(part, ":")
			var host string
			var rangeStr string

			if lastColon != -1 {
				host = part[:lastColon]
				rangeStr = part[lastColon+1:]
			} else {
				rangeStr = part
			}

			rangeParts := strings.Split(rangeStr, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(rangeParts[0])
				end, err2 := strconv.Atoi(rangeParts[1])
				if err1 == nil && err2 == nil && start <= end {
					for i := start; i <= end; i++ {
						if host != "" {
							result = append(result, fmt.Sprintf("%s:%d", host, i))
						} else {
							result = append(result, fmt.Sprintf(":%d", i))
						}
					}
					// IMPORTANT: continue here prevents adding the raw part
					continue
				}
			}
			// If we are here, it means it looked like a range but failed to parse.
			// Log warning and skip it, DO NOT add as raw string.
			log.Printf("Warning: Invalid port range format: %s (skipping)", part)
			continue
		}

		// Not a range, add as is
		result = append(result, part)
	}
	return result
}

// handleDropDPI and handleSession remain largely the same,
// but handleDropDPI no longer needs to peek for HTTP since we are already in HTTP context.
// However, handleDropDPI expects the first packet to be Length+Encrypted.
// Our WebSocketConn provides a stream that starts with exactly that (as sent by client).

func handleDropDPI(conn net.Conn) {
	// We need to peek at the first packet to get SessionID.
	// The protocol is: [Length][Encrypted]
	// Encrypted contains: [SessionID]...

	// Since we are using WebSocketConn, we can't easily "Peek" without consuming.
	// But we don't need to "Peek" to decide protocol anymore. We KNOW it is DropDPI.
	// We just need to read the first packet to get SessionID.

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
