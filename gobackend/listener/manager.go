// Package listener provides a thread-safe pool of multi-protocol network listeners.
//
// Supported protocols: raw TCP, TLS-wrapped TCP, HTTP-beacon (POST-based).
// Each listener is identified by a UUID and bound to a user-supplied host:port.
// Accepted connections are handed off to the session manager.
package listener

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)

// Protocol constants match the Python side (core/reverse_shell.py).
const (
	ProtoTCP  = "tcp"
	ProtoSSL  = "ssl"
	ProtoHTTP = "http"
)

// Listener represents a single bound socket accepting reverse-shell connections.
type Listener struct {
	ID        string    `json:"id"`
	Protocol  string    `json:"protocol"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Running   bool      `json:"running"`
	CreatedAt time.Time `json:"created_at"`

	ln       net.Listener
	cancel   context.CancelFunc
	onAccept func(conn net.Conn, proto string) // callback → session manager
}

// Manager owns the listener pool. All methods are safe for concurrent use.
type Manager struct {
	mu        sync.RWMutex
	listeners map[string]*Listener
	onAccept  func(net.Conn, string)
}

// NewManager creates a Manager. onAccept is called for every accepted connection.
func NewManager() *Manager {
	return &Manager{
		listeners: make(map[string]*Listener),
	}
}

// SetAcceptCallback wires accepted connections into the session manager.
func (m *Manager) SetAcceptCallback(fn func(net.Conn, string)) {
	m.mu.Lock()
	m.onAccept = fn
	m.mu.Unlock()
}

// Start binds a listener on host:port for the given protocol.
// Returns the listener's UUID.
func (m *Manager) Start(proto, host string, port int) (string, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	id := newUUID()

	var ln net.Listener
	var err error

	switch proto {
	case ProtoTCP:
		ln, err = net.Listen("tcp", addr)
	case ProtoSSL:
		ln, err = tlsListen(addr)
	case ProtoHTTP:
		ln, err = net.Listen("tcp", addr)
	default:
		return "", fmt.Errorf("unsupported protocol: %q", proto)
	}

	if err != nil {
		return "", fmt.Errorf("listen %s on %s: %w", proto, addr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	l := &Listener{
		ID:        id,
		Protocol:  proto,
		Host:      host,
		Port:      port,
		Running:   true,
		CreatedAt: time.Now().UTC(),
		ln:        ln,
		cancel:    cancel,
	}

	m.mu.Lock()
	m.listeners[id] = l
	onAccept := m.onAccept
	m.mu.Unlock()

	go l.acceptLoop(ctx, onAccept)

	log.Printf("listener %s started (%s://%s)", id[:8], proto, addr)
	return id, nil
}

// Stop terminates a listener by ID.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	l, ok := m.listeners[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("listener %q not found", id)
	}
	delete(m.listeners, id)
	m.mu.Unlock()

	l.cancel()
	if err := l.ln.Close(); err != nil {
		return fmt.Errorf("close listener: %w", err)
	}
	l.Running = false
	log.Printf("listener %s stopped", id[:8])
	return nil
}

// List returns a snapshot of all listeners.
func (m *Manager) List() []Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Listener, 0, len(m.listeners))
	for _, l := range m.listeners {
		out = append(out, *l)
	}
	return out
}

// Shutdown stops all listeners immediately.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, l := range m.listeners {
		l.cancel()
		l.ln.Close()
		delete(m.listeners, id)
	}
}

func (l *Listener) acceptLoop(ctx context.Context, onAccept func(net.Conn, string)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("listener %s accept error: %v", l.ID[:8], err)
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}

		if onAccept != nil {
			go onAccept(conn, l.Protocol)
		}
	}
}

// tlsListen generates an ephemeral self-signed cert and starts a TLS listener.
func tlsListen(addr string) (net.Listener, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("rsa key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("cert create: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("key pair: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	return tls.Listen("tcp", addr, cfg)
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
