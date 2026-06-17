// Package session tracks live reverse-shell connections with per-session
// read/write buffers consumed by the Python GUI through the REST API.
package session

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Session represents a single reverse-shell connection.
type Session struct {
	ID        string    `json:"id"`
	Protocol  string    `json:"protocol"`
	PeerIP    string    `json:"peer_ip"`
	PeerPort  int       `json:"peer_port"`
	Alive     bool      `json:"alive"`
	CreatedAt time.Time `json:"created_at"`

	conn   net.Conn
	output chan string // buffered stdout lines
	mu     sync.Mutex
}

// Manager owns the session pool.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewManager creates a session Manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
	}
}

// Accept is called by the listener when a new connection arrives.
func (m *Manager) Accept(conn net.Conn, proto string) *Session {
	now := time.Now().UTC()
	tcpAddr, _ := conn.RemoteAddr().(*net.TCPAddr)
	peerIP := ""
	peerPort := 0
	if tcpAddr != nil {
		peerIP = tcpAddr.IP.String()
		peerPort = tcpAddr.Port
	}

	s := &Session{
		ID:        newSID(),
		Protocol:  proto,
		PeerIP:    peerIP,
		PeerPort:  peerPort,
		Alive:     true,
		CreatedAt: now,
		conn:      conn,
		output:    make(chan string, 256),
	}

	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()

	go s.readLoop()
	log.Printf("session %s opened (%s://%s:%d)", s.ID[:8], proto, peerIP, peerPort)
	return s
}

func (s *Session) readLoop() {
	reader := bufio.NewReader(s.conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("session %s read error: %v", s.ID[:8], err)
			}
			s.close()
			return
		}
		select {
		case s.output <- line:
		default:
			// buffer full → drop oldest
			<-s.output
			s.output <- line
		}
	}
}

// Send writes a command to the session's socket.
func (s *Session) Send(data string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Alive {
		return fmt.Errorf("session %s is closed", s.ID[:8])
	}
	_, err := s.conn.Write([]byte(data))
	return err
}

// Drain returns buffered output and clears the buffer.
func (s *Session) Drain() []string {
	var lines []string
	for {
		select {
		case line := <-s.output:
			lines = append(lines, line)
		default:
			return lines
		}
	}
}

// Kill terminates the session.
func (s *Session) Kill() {
	s.close()
}

func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Alive {
		return
	}
	s.Alive = false
	s.conn.Close()
	close(s.output)
	log.Printf("session %s closed", s.ID[:8])
}

// Get retrieves a session by ID.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// ListSnap returns a snapshot of all sessions.
func (m *Manager) ListSnap() []Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		s.mu.Lock()
		cp := Session{
			ID: s.ID, Protocol: s.Protocol,
			PeerIP: s.PeerIP, PeerPort: s.PeerPort,
			Alive: s.Alive, CreatedAt: s.CreatedAt,
		}
		s.mu.Unlock()
		out = append(out, cp)
	}
	return out
}

// Shutdown kills every session.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		s.close()
	}
	m.sessions = make(map[string]*Session)
}

func newSID() string {
	b := make([]byte, 8)
	// simple unique id, sufficient for local-only session tracking
	for i := range b {
		b[i] = byte(time.Now().UnixNano()>>(i*2)) ^ byte(i*7+3)
	}
	return fmt.Sprintf("%016x", b)
}
