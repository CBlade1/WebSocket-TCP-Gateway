package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultLimit        = 2048
	defaultMessageLimit = 1024 * 1024
	pingInterval        = 25 * time.Second
	pongTimeout         = 90 * time.Second
	writeTimeout        = 15 * time.Second
)

type route struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Target string `json:"target"`
}

type config struct {
	Listen              []string `json:"listen"`
	Routes              []route  `json:"routes"`
	AllowedHosts        []string `json:"allowed_hosts"`
	AllowedOrigins      []string `json:"allowed_origins"`
	TrustedProxies      []string `json:"trusted_proxies"`
	RequireTrustedProxy bool     `json:"require_trusted_proxy"`
	MaxConnections      int      `json:"max_connections"`
	MaxMessageBytes     int64    `json:"max_message_bytes"`
}

type gateway struct {
	cfg      config
	trusted  []netip.Prefix
	slots    chan struct{}
	upgrades websocket.Upgrader
}

func loadConfig(path string) (config, error) {
	var cfg config
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return cfg, errors.New("unexpected content after configuration")
		}
		return cfg, err
	}
	return cfg, nil
}

func newGateway(cfg config) (*gateway, error) {
	if len(cfg.Listen) == 0 || len(cfg.Routes) == 0 {
		return nil, errors.New("listen and routes must not be empty")
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = defaultLimit
	}
	if cfg.MaxConnections < 1 || cfg.MaxConnections > 100000 {
		return nil, errors.New("max_connections must be between 1 and 100000")
	}
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = defaultMessageLimit
	}
	if cfg.MaxMessageBytes < 1 || cfg.MaxMessageBytes > 64*1024*1024 {
		return nil, errors.New("max_message_bytes must be between 1 and 67108864")
	}
	seenListen := map[string]bool{}
	for _, addr := range cfg.Listen {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("listener %q: %w", addr, err)
		}
		if seenListen[addr] {
			return nil, fmt.Errorf("duplicate listener: %s", addr)
		}
		seenListen[addr] = true
	}
	seenPath := map[string]bool{}
	for _, r := range cfg.Routes {
		if r.Name == "" || r.Path == "" || r.Target == "" {
			return nil, errors.New("route name, path and target are required")
		}
		if r.Path == "/healthz" || !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "?#") {
			return nil, fmt.Errorf("invalid route path %q", r.Path)
		}
		if seenPath[r.Path] {
			return nil, fmt.Errorf("duplicate route path %q", r.Path)
		}
		seenPath[r.Path] = true
		host, port, err := net.SplitHostPort(r.Target)
		if err != nil {
			return nil, fmt.Errorf("route %q: invalid TCP target: %w", r.Name, err)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("route %q: TCP target must be a loopback IP", r.Name)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("route %q: invalid target port", r.Name)
		}
	}
	trusted := make([]netip.Prefix, 0, len(cfg.TrustedProxies))
	for _, cidr := range cfg.TrustedProxies {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
		}
		trusted = append(trusted, prefix.Masked())
	}
	if cfg.RequireTrustedProxy && len(trusted) == 0 {
		return nil, errors.New("require_trusted_proxy needs trusted_proxies")
	}
	for _, s := range cfg.AllowedOrigins {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("invalid origin %q: use scheme://host[:port]", s)
		}
	}
	g := &gateway{cfg: cfg, trusted: trusted, slots: make(chan struct{}, cfg.MaxConnections)}
	g.upgrades = websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096, EnableCompression: false, CheckOrigin: g.originAllowed}
	return g, nil
}

func (g *gateway) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	} // Native WS clients often do not send Origin.
	for _, allowed := range g.cfg.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func (g *gateway) fromTrustedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range g.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (g *gateway) permittedHost(host string) bool {
	if len(g.cfg.AllowedHosts) == 0 {
		return true
	}
	for _, allowed := range g.cfg.AllowedHosts {
		if strings.EqualFold(host, allowed) {
			return true
		}
	}
	return false
}

func (g *gateway) handleUpgrade(w http.ResponseWriter, r *http.Request, rt route) {
	if r.Method != http.MethodGet || !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	if !g.permittedHost(r.Host) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	if g.cfg.RequireTrustedProxy && !g.fromTrustedPeer(r) {
		http.Error(w, "proxy required", http.StatusForbidden)
		return
	}
	if !g.originAllowed(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "connection limit reached", http.StatusServiceUnavailable)
		return
	}

	// Connect before upgrading so failed targets produce a useful HTTP response.
	tcp, err := net.DialTimeout("tcp", rt.Target, 3*time.Second)
	if err != nil {
		http.Error(w, "target unavailable", http.StatusBadGateway)
		return
	}
	defer tcp.Close()
	if c, ok := tcp.(*net.TCPConn); ok {
		_ = c.SetNoDelay(true)
		_ = c.SetKeepAlive(true)
	}

	ws, err := g.upgrades.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.EnableWriteCompression(false)
	ws.SetReadLimit(g.cfg.MaxMessageBytes)
	_ = ws.SetReadDeadline(time.Now().Add(pongTimeout))
	ws.SetPongHandler(func(string) error { return ws.SetReadDeadline(time.Now().Add(pongTimeout)) })

	done := make(chan struct{})
	var closeOnce sync.Once
	stop := func() { closeOnce.Do(func() { close(done); _ = tcp.Close(); _ = ws.Close() }) }
	defer stop()

	// One reader and one data writer per WebSocket. Control frames may be sent concurrently.
	go func() {
		defer stop()
		for {
			kind, msg, err := ws.NextReader()
			if err != nil {
				return
			}
			if kind != websocket.BinaryMessage {
				return
			}
			if _, err := io.CopyBuffer(tcp, msg, make([]byte, 32*1024)); err != nil {
				return
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
					stop()
					return
				}
			}
		}
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := tcp.Read(buf)
		if n > 0 {
			if e := ws.SetWriteDeadline(time.Now().Add(writeTimeout)); e != nil {
				return
			}
			if e := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); e != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (g *gateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// This is a process liveness check, not a check of every configured target.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	for _, rt := range g.cfg.Routes {
		routeCopy := rt
		mux.HandleFunc(routeCopy.Path, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != routeCopy.Path {
				http.NotFound(w, r)
				return
			}
			g.handleUpgrade(w, r, routeCopy)
		})
	}
	return mux
}

func main() {
	path := flag.String("config", "config.json", "JSON configuration file")
	flag.Parse()
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	g, err := newGateway(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	servers := make([]*http.Server, 0, len(cfg.Listen))
	listeners := make([]net.Listener, 0, len(cfg.Listen))
	for _, addr := range cfg.Listen {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			log.Fatalf("listen %s: %v", addr, err)
		}
		listeners = append(listeners, ln)
		servers = append(servers, &http.Server{Handler: g.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 * 1024})
	}
	for i, ln := range listeners {
		srv := servers[i]
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("http server stopped: %v", err)
			}
		}()
		log.Printf("listening on %s", ln.Addr())
	}
	<-ctx.Done()
	log.Println("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
}
