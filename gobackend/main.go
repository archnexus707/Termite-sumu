// Termite-sumu Go Backend — high-concurrency listener/session/payload engine.
//
// Serves a REST API on 127.0.0.1:9120 consumed by the Python PyQt6 GUI.
// All network I/O lives here so the GUI thread never blocks on socket ops.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"termite-sumu-gobackend/api"
	"termite-sumu-gobackend/listener"
	"termite-sumu-gobackend/payload"
	"termite-sumu-gobackend/session"
)

const (
	addr            = "127.0.0.1:9120"
	readTimeout     = 15 * time.Second
	writeTimeout    = 15 * time.Second
	shutdownTimeout = 10 * time.Second
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("[go-backend] ")

	lm := listener.NewManager()
	sm := session.NewManager()
	pg := payload.NewGenerator()

	mux := api.NewRouter(lm, sm, pg)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	// Graceful shutdown on SIGINT / SIGTERM
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server crashed: %v", err)
		}
	}()

	<-done
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	lm.Shutdown()
	sm.Shutdown()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown failed: %v", err)
	}
	log.Println("stopped cleanly")
}
