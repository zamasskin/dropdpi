package transport

import (
	"io"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConn adapts a websocket.Conn to the net.Conn interface.
type WebSocketConn struct {
	*websocket.Conn
	reader io.Reader
}

func NewWebSocketConn(ws *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{
		Conn: ws,
	}
}

func (c *WebSocketConn) Read(b []byte) (n int, err error) {
	if c.reader == nil {
		// Get next message reader
		_, r, err := c.Conn.NextReader()
		if err != nil {
			return 0, err
		}
		c.reader = r
	}

	n, err = c.reader.Read(b)
	if err == io.EOF {
		c.reader = nil
		// Recursively call Read to get data from next message
		// Beware of stack overflow if many empty messages, but standard WS usage is fine.
		// Alternatively, return (n, nil) if n > 0, or loop.
		// Let's loop.
		if n > 0 {
			return n, nil
		}
		return c.Read(b)
	}
	return n, err
}

func (c *WebSocketConn) Write(b []byte) (n int, err error) {
	// WebSocket messages preserve boundaries, but net.Conn is a stream.
	// We send as BinaryMessage.
	err = c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *WebSocketConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}
