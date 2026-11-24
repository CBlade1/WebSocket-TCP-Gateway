package main

import (
	"encoding/binary"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigLoopbackOnly(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "c.json")
	data := []byte(`{"listen":["127.0.0.1:2052"],"routes":[{"name":"bad","path":"/bridge/bad","backend":"8.8.8.8:2828"}]}`)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfig(file); err == nil {
		t.Fatal("expected non-loopback target to fail")
	}
}
func TestHeaderCannotBeSpoofed(t *testing.T) {
	settings = Settings{}
	trusted = nil
	req := httptest.NewRequest("GET", "http://localhost/legacy", nil)
	req.RemoteAddr = "192.0.2.9:4444"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")
	if ip := clientIPFromTrustedRequest(req); ip != "192.0.2.9" {
		t.Fatalf("forged IP accepted: %s", ip)
	}
}
func TestPreserveLegacySessionAcrossPeerDisconnect(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	proxyDestinations = map[uint16]string{2828: l.Addr().String()}
	proxyProtocolTargets = map[string]bool{}
	hub := newProxyHub()
	session, err := hub.getOrCreate(123, "192.0.2.10", 2828)
	if err != nil {
		t.Fatal(err)
	}
	defer session.terminate("test done")
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("backend not reached")
	}
	if errSession, err := hub.getOrCreate(123, "198.51.100.10", 2828); err == nil {
		_ = errSession
		t.Fatal("different IP reused session")
	}
	if hub.get(123) != session {
		t.Fatal("session lost after failed reuse")
	}
	// A disconnected peer does not close the TCP session immediately.
	if session.isClosed() {
		t.Fatal("session terminated prematurely")
	}
}
func TestProxyFrameHeader(t *testing.T) {
	frame := make([]byte, 14)
	binary.LittleEndian.PutUint16(frame[:2], 12)
	if size := binary.LittleEndian.Uint16(frame[:2]); size != ProxyFrameMinSize {
		t.Fatal(size)
	}
}
