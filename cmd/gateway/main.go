package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type Route struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Backend       string `json:"backend"`
	LegacyPort    uint16 `json:"legacy_port,omitempty"`
	ProxyProtocol bool   `json:"proxy_protocol,omitempty"`
}
type Settings struct {
	Listen            []string `json:"listen"`
	Routes            []Route  `json:"routes"`
	LegacyProxyPath   string   `json:"legacy_proxy_path"`
	LegacyProxyAtRoot bool     `json:"legacy_proxy_at_root"`
	RequireCloudflare bool     `json:"require_cloudflare"`
	TrustedProxies    []string `json:"trusted_proxies"`
	AllowedOrigins    []string `json:"allowed_origins"`
	AllowedHosts      []string `json:"allowed_hosts"`
	MaxConnections    int      `json:"max_connections"`
	MaxFrameBytes     int64    `json:"max_frame_bytes"`
	MaxIdleSeconds    int      `json:"max_idle_seconds"`
}

var settings Settings
var trusted []*net.IPNet
var gate = make(chan struct{}, 10000)
var proxyProtocolTargets map[string]bool
var serverMu sync.Mutex
var allServers []*http.Server

func loadConfig(filename string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&settings); err != nil {
		return err
	}
	if len(settings.Listen) == 0 || len(settings.Routes) == 0 {
		return errors.New("listen and routes must not be empty")
	}
	if settings.LegacyProxyPath == "" {
		settings.LegacyProxyPath = "/legacy"
	}
	if settings.MaxConnections <= 0 {
		settings.MaxConnections = 2048
	}
	if settings.MaxConnections > 10000 {
		return errors.New("max_connections must be <= 10000")
	}
	gate = make(chan struct{}, settings.MaxConnections)
	if settings.MaxFrameBytes <= 0 {
		settings.MaxFrameBytes = 1024 * 1024
	}
	if settings.MaxFrameBytes > 64*1024*1024 {
		return errors.New("max_frame_bytes must be <= 64 MiB")
	}
	if settings.MaxIdleSeconds <= 0 {
		settings.MaxIdleSeconds = 120
	}
	for _, cidr := range settings.TrustedProxies {
		_, ipnet, e := net.ParseCIDR(cidr)
		if e != nil {
			return fmt.Errorf("trusted proxy %q: %w", cidr, e)
		}
		trusted = append(trusted, ipnet)
	}
	if settings.RequireCloudflare && len(trusted) == 0 {
		return errors.New("require_cloudflare needs trusted_proxies CIDRs; see docs/security.md")
	}
	proxyDestinations = make(map[uint16]string)
	proxyProtocolTargets = make(map[string]bool)
	seen := map[string]bool{}
	for _, r := range settings.Routes {
		if r.Name == "" || !strings.HasPrefix(r.Path, "/") || r.Backend == "" {
			return fmt.Errorf("route %q: name, absolute path and backend required", r.Name)
		}
		if seen[r.Path] || r.Path == settings.LegacyProxyPath || r.Path == "/healthz" {
			return fmt.Errorf("duplicate or reserved path %q", r.Path)
		}
		seen[r.Path] = true
		host, port, e := net.SplitHostPort(r.Backend)
		if e != nil || port == "" {
			return fmt.Errorf("route %q: invalid backend", r.Name)
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("route %q: backend must be loopback IP to avoid unintended proxying", r.Name)
		}
		if r.LegacyPort != 0 {
			if _, ok := proxyDestinations[r.LegacyPort]; ok {
				return fmt.Errorf("duplicate legacy port %d", r.LegacyPort)
			}
			proxyDestinations[r.LegacyPort] = r.Backend
		}
		if r.ProxyProtocol {
			proxyProtocolTargets[r.Backend] = true
		}
	}
	for _, listen := range settings.Listen {
		if _, _, e := net.SplitHostPort(listen); e != nil {
			return fmt.Errorf("bad listener %q: %w", listen, e)
		}
	}
	return nil
}

func trustedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
func clientIPFromTrustedRequest(r *http.Request) string {
	if trustedPeer(r) {
		if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
			if ip := net.ParseIP(v); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	return host
}
func allowUpgrade(r *http.Request) bool {
	if settings.RequireCloudflare && !trustedPeer(r) {
		return false
	}
	if len(settings.AllowedHosts) > 0 {
		for _, host := range settings.AllowedHosts {
			if strings.EqualFold(r.Host, host) {
				return true
			}
		}
		return false
	}
	return true
}
func permittedOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	} // native clients normally have no Origin header
	for _, allowed := range settings.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}
func shouldSendProxyHeader(target string) bool { return proxyProtocolTargets[target] }
func maxWSMessage() int64                      { return settings.MaxFrameBytes }

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok\n"))
	})
	for _, route := range settings.Routes {
		r := route
		mux.HandleFunc(r.Path, func(w http.ResponseWriter, req *http.Request) { rawBridge(w, req, r) })
	}
	legacyHandler := handleProxyWebSocket()
	mux.HandleFunc(settings.LegacyProxyPath, func(w http.ResponseWriter, r *http.Request) {
		if !admit(w, r) {
			return
		}
		defer release()
		legacyHandler(w, r)
	})
	if settings.LegacyProxyAtRoot {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			if !admit(w, r) {
				return
			}
			defer release()
			legacyHandler(w, r)
		})
	}
	return mux
}
func admit(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "websocket upgrade required", 400)
		return false
	}
	if !allowUpgrade(r) {
		http.Error(w, "untrusted origin", 403)
		return false
	}
	if !permittedOrigin(r) {
		http.Error(w, "origin denied", 403)
		return false
	}
	select {
	case gate <- struct{}{}:
		return true
	default:
		http.Error(w, "capacity reached", 503)
		return false
	}
}
func release() { <-gate }

func rawBridge(w http.ResponseWriter, r *http.Request, route Route) {
	if !admit(w, r) {
		return
	}
	defer release()
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.EnableWriteCompression(false)
	ws.SetReadLimit(settings.MaxFrameBytes)
	clientIP := clientIPFromTrustedRequest(r)
	backend, err := net.DialTimeout("tcp", route.Backend, 5*time.Second)
	if err != nil {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1011, "backend unavailable"), time.Now().Add(time.Second))
		return
	}
	defer backend.Close()
	if tcp, ok := backend.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
	}
	if route.ProxyProtocol {
		header := buildPROXYv2Header(clientIP, route.Backend)
		if len(header) == 0 || writeAll(backend, header) != nil {
			return
		}
	}
	end := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(end); _ = backend.Close(); _ = ws.Close() }) }
	ws.SetReadLimit(settings.MaxFrameBytes)
	_ = ws.SetReadDeadline(time.Now().Add(time.Duration(settings.MaxIdleSeconds) * time.Second))
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(time.Duration(settings.MaxIdleSeconds) * time.Second))
	})
	go func() {
		defer stop()
		for {
			typ, reader, e := ws.NextReader()
			if e != nil {
				return
			}
			if typ != websocket.BinaryMessage {
				continue
			}
			if _, e = copyLimit(backend, reader, settings.MaxFrameBytes); e != nil {
				return
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-end:
				return
			case <-ticker.C:
				if ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
					stop()
					return
				}
			}
		}
	}()
	buf := make([]byte, 32*1024)
	for {
		n, e := backend.Read(buf)
		if n > 0 {
			if ws.SetWriteDeadline(time.Now().Add(15*time.Second)) != nil || ws.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil {
				break
			}
		}
		if e != nil {
			break
		}
	}
	stop()
}
func copyLimit(dst net.Conn, src io.Reader, limit int64) (int64, error) {
	// The WebSocket library enforces the message read limit. This additional
	// bound protects callers that replace the WebSocket reader in the future.
	n, err := io.CopyBuffer(dst, io.LimitReader(src, limit+1), make([]byte, 32*1024))
	if n > limit {
		return n, fmt.Errorf("websocket message exceeds limit")
	}
	return n, err
}

func main() {
	configFile := flag.String("config", "config.json", "configuration file")
	flag.Parse()
	if e := loadConfig(*configFile); e != nil {
		log.Fatal(e)
	}
	serverHandler := handler()
	for _, addr := range settings.Listen {
		listener, e := net.Listen("tcp", addr)
		if e != nil {
			for _, srv := range allServers {
				_ = srv.Close()
			}
			log.Fatalf("bind %s: %v", addr, e)
		}
		srv := &http.Server{Addr: addr, Handler: serverHandler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 * 1024}
		serverMu.Lock()
		allServers = append(allServers, srv)
		serverMu.Unlock()
		go func(s *http.Server, l net.Listener) {
			log.Printf("listening on %s", l.Addr())
			if e := s.Serve(l); e != nil && !errors.Is(e, http.ErrServerClosed) {
				log.Printf("listener %s: %v", s.Addr, e)
			}
		}(srv, listener)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	log.Println("shutting down listeners")
	for _, srv := range allServers {
		_ = srv.Close()
	}
}
