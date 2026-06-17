// Package api provides the REST handlers consumed by the Python GUI bridge.
package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"termite-sumu-gobackend/listener"
	"termite-sumu-gobackend/payload"
	"termite-sumu-gobackend/session"
)

func jsonResp(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	jsonResp(w, status, map[string]string{"error": msg})
}

// NewRouter builds the HTTP mux with all routes registered.
func NewRouter(lm *listener.Manager, sm *session.Manager, pg *payload.Generator) http.Handler {
	mux := http.NewServeMux()

	lm.SetAcceptCallback(func(conn net.Conn, proto string) {
		sm.Accept(conn, proto)
	})

	h := &handler{lm: lm, sm: sm, pg: pg}

	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/listeners", h.handleListeners)
	mux.HandleFunc("/listeners/", h.handleListenerByID)
	mux.HandleFunc("/sessions", h.handleSessions)
	mux.HandleFunc("/sessions/", h.handleSessionByID)
	mux.HandleFunc("/payloads/types", h.payloadTypes)
	mux.HandleFunc("/payloads/generate", h.generatePayload)

	return mux
}

type handler struct {
	lm *listener.Manager
	sm *session.Manager
	pg *payload.Generator
}

// ── Health ──────────────────────────────────────────────────────────────────

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, 200, map[string]interface{}{
		"status":    "ok",
		"uptime_s":  time.Since(startTime).Seconds(),
		"listeners": len(h.lm.List()),
		"sessions":  len(h.sm.ListSnap()),
	})
}

var startTime = time.Now()

// ── Listeners ───────────────────────────────────────────────────────────────

func (h *handler) handleListeners(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonResp(w, 200, h.lm.List())
	case http.MethodPost:
		var req struct {
			Protocol string `json:"protocol"`
			Host     string `json:"host"`
			Port     int    `json:"port"`
		}
		if ct := r.Header.Get("Content-Type"); ct == "application/json" {
			json.NewDecoder(r.Body).Decode(&req)
		} else {
			req.Protocol = r.URL.Query().Get("protocol")
			req.Host = r.URL.Query().Get("host")
			req.Port, _ = strconv.Atoi(r.URL.Query().Get("port"))
		}
		if req.Host == "" {
			req.Host = "0.0.0.0"
		}
		if req.Port == 0 {
			req.Port = 4444
		}
		id, err := h.lm.Start(req.Protocol, req.Host, req.Port)
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		jsonResp(w, 201, map[string]string{"id": id})
	default:
		jsonErr(w, 405, "method not allowed")
	}
}

func (h *handler) handleListenerByID(w http.ResponseWriter, r *http.Request) {
	// path: /listeners/<id>
	id := strings.TrimPrefix(r.URL.Path, "/listeners/")
	if id == "" {
		jsonErr(w, 400, "missing listener id")
		return
	}
	if r.Method != http.MethodDelete {
		jsonErr(w, 405, "only DELETE supported")
		return
	}
	if err := h.lm.Stop(id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	jsonResp(w, 200, map[string]string{"status": "stopped"})
}

// ── Sessions ────────────────────────────────────────────────────────────────

func (h *handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, 405, "only GET supported")
		return
	}
	jsonResp(w, 200, h.sm.ListSnap())
}

func (h *handler) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	// path: /sessions/<id>[/output|/send]
	id, action := parseSessionPath(r.URL.Path)
	if id == "" {
		jsonErr(w, 400, "missing session id")
		return
	}

	switch {
	case action == "output" && r.Method == http.MethodGet:
		s, ok := h.sm.Get(id)
		if !ok {
			jsonErr(w, 404, "session not found")
			return
		}
		jsonResp(w, 200, map[string]interface{}{
			"session_id": s.ID,
			"peer":       s.PeerIP + ":" + strconv.Itoa(s.PeerPort),
			"alive":      s.Alive,
			"lines":      s.Drain(),
		})

	case action == "send" && r.Method == http.MethodPost:
		s, ok := h.sm.Get(id)
		if !ok {
			jsonErr(w, 404, "session not found")
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		cmd := strings.TrimSpace(string(body))
		if cmd == "" {
			cmd = r.URL.Query().Get("cmd")
		}
		if cmd == "" {
			jsonErr(w, 400, "empty command")
			return
		}
		if !strings.HasSuffix(cmd, "\n") {
			cmd += "\n"
		}
		if err := s.Send(cmd); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		jsonResp(w, 200, map[string]string{"sent": cmd})

	case action == "" && r.Method == http.MethodDelete:
		s, ok := h.sm.Get(id)
		if !ok {
			jsonErr(w, 404, "session not found")
			return
		}
		s.Kill()
		jsonResp(w, 200, map[string]string{"status": "killed"})

	default:
		jsonErr(w, 404, "unknown session endpoint")
	}
}

// parseSessionPath splits /sessions/<id>/output → (id, "output")
func parseSessionPath(path string) (id, action string) {
	s := strings.TrimPrefix(path, "/sessions/")
	parts := strings.SplitN(s, "/", 2)
	id = parts[0]
	if len(parts) > 1 {
		action = parts[1]
	}
	return
}

// ── Payloads ────────────────────────────────────────────────────────────────

func (h *handler) payloadTypes(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, 200, h.pg.Types())
}

func (h *handler) generatePayload(w http.ResponseWriter, r *http.Request) {
	ptype := r.URL.Query().Get("type")
	lhost := r.URL.Query().Get("lhost")
	lport, _ := strconv.Atoi(r.URL.Query().Get("lport"))
	if ptype == "" {
		ptype = "bash"
	}
	if lhost == "" {
		lhost = "127.0.0.1"
	}
	if lport == 0 {
		lport = 4444
	}
	result, err := h.pg.Generate(ptype, lhost, lport)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]string{
		"type":    ptype,
		"lhost":   lhost,
		"lport":   strconv.Itoa(lport),
		"payload": result,
	})
}
