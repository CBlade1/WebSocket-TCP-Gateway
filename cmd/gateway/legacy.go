package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	GameWsPort  = "0.0.0.0:8080"
	LoginWsPort = "0.0.0.0:8880"

	// Cloudflare-supported HTTP WebSocket ports.
	ProxyWsPortA = "0.0.0.0:2052"
	ProxyWsPortB = "0.0.0.0:2082"
	ProxyWsPortC = "0.0.0.0:2086"

	LoginTcpHost = "127.0.0.1:7171"
	GameTcpHost  = "127.0.0.1:7172"

	EnableLogging = false

	BufferSize = 32 * 1024
	WSReadLimit = 66 * 1024

	LoginMaxConnPerIP     = 0
	LoginMaxAttemptsPerIP = 0
	LoginAttemptWindow    = 30 * time.Second
	LoginMinReconnectGap  = 1000 * time.Millisecond

	GameMaxConnPerIP     = 0
	GameMaxAttemptsPerIP = 0
	GameAttemptWindow    = 3 * time.Second
	GameMinReconnectGap  = 50 * time.Millisecond

	IPStateIdleExpiry = 1 * time.Minute

	// Keep heartbeat well below common proxy idle windows.
	WSPongWait   = 1800 * time.Second
	WSPingPeriod = 25 * time.Second
	WSWriteWait  = 300 * time.Second

	ProxyFrameMinSize = 12
	ProxyMaxFrameSize = 65535

	// Keep session alive across Cloudflare 1001 reconnect windows (edge restarts/rotations).
	ProxySessionOrphanTTL  = 10 * time.Minute
	ProxySessionCheckEvery = 5 * time.Second
	ProxyMaxPendingPackets = 256
	ProxyPeerWriteQueueCap = 128
)

const ProxySessionEndPacketID uint32 = 0xFFFFFFFF

var wsWriteBufferPool sync.Pool

var upgrader = websocket.Upgrader{
	ReadBufferSize:  BufferSize,
	WriteBufferSize: BufferSize,
	WriteBufferPool: &wsWriteBufferPool,
	CheckOrigin: func(r *http.Request) bool {
		return permittedOrigin(r)
	},
}

var proxyDestinations = map[uint16]string{
	7171: LoginTcpHost,
	7172: GameTcpHost,
	8880: LoginTcpHost,
	8080: GameTcpHost,
}

type ipState struct {
	active       int32
	lastSeenUnix int64

	mu          sync.Mutex
	windowStart time.Time
	attempts    int
	lastAttempt time.Time
}

type limiterConfig struct {
	name             string
	maxConnPerIP     int32
	maxAttemptsPerIP int
	attemptWindow    time.Duration
	minReconnectGap  time.Duration
}

type limiterBucket struct {
	cfg    limiterConfig
	states sync.Map // map[string]*ipState
}

func newLimiter(name string, maxConn int32, maxAttempts int, attemptWindow, minGap time.Duration) *limiterBucket {
	return &limiterBucket{
		cfg: limiterConfig{
			name:             name,
			maxConnPerIP:     maxConn,
			maxAttemptsPerIP: maxAttempts,
			attemptWindow:    attemptWindow,
			minReconnectGap:  minGap,
		},
	}
}

var loginLimiter = newLimiter("login", LoginMaxConnPerIP, LoginMaxAttemptsPerIP, LoginAttemptWindow, LoginMinReconnectGap)
var gameLimiter = newLimiter("game", GameMaxConnPerIP, GameMaxAttemptsPerIP, GameAttemptWindow, GameMinReconnectGap)

var proxyHubGlobal = newProxyHub()

// packetBufPool recycles packet body buffers across connections.
var packetBufPool = sync.Pool{
	New: func() any {
		// Two-byte protocol length prefix plus the maximum uint16 body.
		buf := make([]byte, 2+65535)
		return &buf
	},
}

func (b *limiterBucket) getIPState(ip string) *ipState {
	v, _ := b.states.LoadOrStore(ip, &ipState{lastSeenUnix: time.Now().Unix()})
	st := v.(*ipState)
	atomic.StoreInt64(&st.lastSeenUnix, time.Now().Unix())
	return st
}

func (b *limiterBucket) allowAttempt(ip string) bool {
	if b.cfg.maxAttemptsPerIP <= 0 {
		return true
	}
	if ip == "" {
		return false
	}

	now := time.Now()
	st := b.getIPState(ip)

	st.mu.Lock()
	defer st.mu.Unlock()

	if !st.lastAttempt.IsZero() && now.Sub(st.lastAttempt) < b.cfg.minReconnectGap {
		st.lastAttempt = now
		return false
	}

	if st.windowStart.IsZero() || now.Sub(st.windowStart) >= b.cfg.attemptWindow {
		st.windowStart = now
		st.attempts = 0
	}

	st.attempts++
	st.lastAttempt = now
	return st.attempts <= b.cfg.maxAttemptsPerIP
}

func (b *limiterBucket) incConn(ip string) bool {
	if b.cfg.maxConnPerIP <= 0 {
		return true
	}
	if ip == "" {
		return false
	}

	st := b.getIPState(ip)
	n := atomic.AddInt32(&st.active, 1)
	if n > b.cfg.maxConnPerIP {
		atomic.AddInt32(&st.active, -1)
		return false
	}
	return true
}

func (b *limiterBucket) decConn(ip string) {
	if ip == "" {
		return
	}

	v, ok := b.states.Load(ip)
	if !ok {
		return
	}

	st := v.(*ipState)
	n := atomic.AddInt32(&st.active, -1)
	if n < 0 {
		atomic.StoreInt32(&st.active, 0)
	}
	atomic.StoreInt64(&st.lastSeenUnix, time.Now().Unix())
}

func (b *limiterBucket) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		nowUnix := time.Now().Unix()
		b.states.Range(func(key, value any) bool {
			st := value.(*ipState)
			active := atomic.LoadInt32(&st.active)
			lastSeen := atomic.LoadInt64(&st.lastSeenUnix)

			if active == 0 && time.Duration(nowUnix-lastSeen)*time.Second > IPStateIdleExpiry {
				b.states.Delete(key)
			}
			return true
		})
	}
}

type wsReader struct {
	conn   *websocket.Conn
	reader io.Reader
}

func (r *wsReader) Read(p []byte) (int, error) {
	for {
		if r.reader != nil {
			n, err := r.reader.Read(p)
			if n > 0 {
				_ = r.conn.SetReadDeadline(time.Now().Add(WSPongWait))
			}
			if err == io.EOF {
				r.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			return n, err
		}

		messageType, reader, err := r.conn.NextReader()
		if err != nil {
			return 0, err
		}
		if messageType != websocket.BinaryMessage {
			continue
		}
		r.reader = reader
	}
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if n == 0 && err == nil {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func copyTCPtoWS(writeBinary func([]byte) error, tcpConn net.Conn) error {
	var headerBuf [2]byte

	for {
		if _, err := io.ReadFull(tcpConn, headerBuf[:]); err != nil {
			return err
		}

		packetLen := binary.LittleEndian.Uint16(headerBuf[:])
		if packetLen == 0 {
			continue
		}

		bufPtr := packetBufPool.Get().(*[]byte)
		totalLen := int(packetLen) + len(headerBuf)
		if totalLen > len(*bufPtr) {
			*bufPtr = make([]byte, totalLen)
		}
		packet := (*bufPtr)[:totalLen]
		copy(packet[:2], headerBuf[:])

		if _, err := io.ReadFull(tcpConn, packet[2:]); err != nil {
			packetBufPool.Put(bufPtr)
			return err
		}

		if err := writeBinary(packet); err != nil {
			packetBufPool.Put(bufPtr)
			return err
		}

		packetBufPool.Put(bufPtr)
	}
}

func buildPROXYv2Header(clientIP string, tcpHost string) []byte {
	if clientIP == "" {
		return nil
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		logMsg("Warning", fmt.Sprintf("Invalid IP: %s", clientIP))
		return nil
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		if strings.Contains(clientIP, ":") {
			parts := strings.Split(clientIP, ":")
			if len(parts) > 0 {
				ip = net.ParseIP(parts[len(parts)-1])
				if ip != nil {
					ipv4 = ip.To4()
				}
			}
		}
		if ipv4 == nil {
			logMsg("Warning", fmt.Sprintf("Cannot convert to IPv4: %s", clientIP))
			return nil
		}
	}

	header := make([]byte, 28)
	copy(header[0:12], []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A})
	header[12] = 0x21 // version 2, PROXY
	header[13] = 0x11 // TCP over IPv4
	binary.BigEndian.PutUint16(header[14:16], 12)
	copy(header[16:20], ipv4)
	copy(header[20:24], []byte{0, 0, 0, 0})
	binary.BigEndian.PutUint16(header[24:26], 0)

	dstPort := uint16(0)
	if _, portStr, err := net.SplitHostPort(tcpHost); err == nil {
		if p, convErr := strconv.Atoi(portStr); convErr == nil && p > 0 && p <= 65535 {
			dstPort = uint16(p)
		}
	}
	if dstPort == 0 {
		if strings.Contains(tcpHost, "7171") {
			dstPort = 7171
		} else {
			dstPort = 7172
		}
	}
	binary.BigEndian.PutUint16(header[26:28], dstPort)

	if EnableLogging {
		logMsg("Proxy", fmt.Sprintf("PROXYv2 for %s -> IP bytes: %s", clientIP, hex.EncodeToString(header[16:20])))
	}

	return header
}

// Direct bridge mode (legacy ws://host:8880 and ws://host:8080)
type Bridge struct {
	wsConn      *websocket.Conn
	tcpConn     net.Conn
	clientIP    string
	tcpHost     string
	limiter     *limiterBucket
	closeChan   chan struct{}
	closeOnce   sync.Once
	releaseOnce sync.Once
}

func NewBridge(ws *websocket.Conn, clientIP string, tcpHost string, limiter *limiterBucket) *Bridge {
	return &Bridge{
		wsConn:    ws,
		clientIP:  clientIP,
		tcpHost:   tcpHost,
		limiter:   limiter,
		closeChan: make(chan struct{}),
	}
}

func (b *Bridge) Start() {
	logMsg("Bridge", fmt.Sprintf("[%s] Connecting to %s for client: %s", b.limiter.cfg.name, b.tcpHost, b.clientIP))

	tcpConn, err := net.DialTimeout("tcp", b.tcpHost, 5*time.Second)
	if err != nil {
		logMsg("Error", fmt.Sprintf("Failed to connect to TFS (%s): %v", b.tcpHost, err))
		b.Close()
		return
	}

	if tcp, ok := tcpConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(60 * time.Second)
	}

	b.tcpConn = tcpConn
	logMsg("Bridge", fmt.Sprintf("[%s] TCP connected to %s for client: %s", b.limiter.cfg.name, b.tcpHost, b.clientIP))

	if shouldSendProxyHeader(b.tcpHost) {
		proxyHeader := buildPROXYv2Header(b.clientIP, b.tcpHost)
		if len(proxyHeader) == 0 {
			b.Close()
			return
		}
		if _, err := b.tcpConn.Write(proxyHeader); err != nil {
			logMsg("Error", fmt.Sprintf("Failed to send PROXYv2 header: %v", err))
			b.Close()
			return
		}
		logMsg("Proxy", fmt.Sprintf("[%s] Sent PROXYv2 header for client: %s", b.limiter.cfg.name, b.clientIP))
	}

	go func() {
		ticker := time.NewTicker(WSPingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-b.closeChan:
				return
			case <-ticker.C:
				if err := b.writePing(); err != nil {
					if !b.isClosed() {
						logMsg("WS Ping Error", fmt.Sprintf("[%s] %s: %v", b.limiter.cfg.name, b.clientIP, err))
					}
					b.Close()
					return
				}
			}
		}
	}()

	go func() {
		defer b.Close()
		_, err := io.Copy(b.tcpConn, &wsReader{conn: b.wsConn})
		if err != nil && !b.isClosed() {
			logMsg("WS->TCP Error", fmt.Sprintf("[%s] %s: %v", b.limiter.cfg.name, b.clientIP, err))
		}
	}()

	go func() {
		defer b.Close()
		err := copyTCPtoWS(b.writeBinaryFrame, b.tcpConn)
		if err != nil && !b.isClosed() {
			logMsg("TCP->WS Error", fmt.Sprintf("[%s] %s: %v", b.limiter.cfg.name, b.clientIP, err))
		}
	}()
}

func (b *Bridge) writeBinaryFrame(packet []byte) error {
	if b.wsConn == nil {
		return net.ErrClosed
	}

	if err := b.wsConn.SetWriteDeadline(time.Now().Add(WSWriteWait)); err != nil {
		return err
	}

	// There is exactly one data writer for a direct bridge. WriteControl is safe
	// concurrently, so the heartbeat does not require a data-write mutex.
	return b.wsConn.WriteMessage(websocket.BinaryMessage, packet)
}

func (b *Bridge) writePing() error {
	if b.wsConn == nil {
		return net.ErrClosed
	}
	return b.wsConn.WriteControl(websocket.PingMessage, nil, time.Now().Add(WSWriteWait))
}

func (b *Bridge) isClosed() bool {
	select {
	case <-b.closeChan:
		return true
	default:
		return false
	}
}

func (b *Bridge) Close() {
	b.closeOnce.Do(func() {
		close(b.closeChan)
		if b.wsConn != nil {
			_ = b.wsConn.Close()
		}
		if b.tcpConn != nil {
			_ = b.tcpConn.Close()
		}
		b.releaseOnce.Do(func() {
			b.limiter.decConn(b.clientIP)
		})
		logMsg("Bridge", fmt.Sprintf("[%s] Closed connection for client: %s", b.limiter.cfg.name, b.clientIP))
	})
}

type proxyHub struct {
	mu       sync.Mutex
	sessions map[uint32]*proxySession
}

func newProxyHub() *proxyHub {
	return &proxyHub{sessions: make(map[uint32]*proxySession)}
}

func (h *proxyHub) get(sessionID uint32) *proxySession {
	h.mu.Lock()
	s := h.sessions[sessionID]
	h.mu.Unlock()
	return s
}

func (h *proxyHub) getOrCreate(sessionID uint32, clientIP string, destPort uint16) (*proxySession, error) {
	if sessionID == 0 {
		return nil, fmt.Errorf("zero session ID reserved")
	}
	h.mu.Lock()
	if existing := h.sessions[sessionID]; existing != nil {
		if existing.clientIP != clientIP || existing.destPort != destPort {
			h.mu.Unlock()
			return nil, fmt.Errorf("session id already used by a different client or destination")
		}
		h.mu.Unlock()
		return existing, nil
	}
	if len(h.sessions) >= 2048 {
		h.mu.Unlock()
		return nil, fmt.Errorf("session capacity reached")
	}
	h.mu.Unlock()

	tcpHost, ok := proxyDestinations[destPort]
	if !ok {
		return nil, fmt.Errorf("unsupported destination port %d", destPort)
	}

	s, err := newProxySession(h, sessionID, clientIP, destPort, tcpHost)
	if err != nil {
		return nil, err
	}

	h.mu.Lock()
	if existing := h.sessions[sessionID]; existing != nil {
		authorized := existing.clientIP == clientIP && existing.destPort == destPort
		h.mu.Unlock()
		s.terminate("duplicate session creator")
		if !authorized {
			return nil, fmt.Errorf("session id already in use")
		}
		return existing, nil
	}
	if len(h.sessions) >= 2048 {
		h.mu.Unlock()
		s.terminate("session capacity reached")
		return nil, fmt.Errorf("session capacity reached")
	}
	h.sessions[sessionID] = s
	h.mu.Unlock()

	s.start()
	return s, nil
}

func (h *proxyHub) remove(sessionID uint32, expected *proxySession) {
	h.mu.Lock()
	if h.sessions[sessionID] == expected {
		delete(h.sessions, sessionID)
	}
	h.mu.Unlock()
}

type proxySession struct {
	hub      *proxyHub
	id       uint32
	clientIP string
	destPort uint16
	tcpHost  string
	tcpConn  net.Conn

	closeOnce sync.Once
	closeCh   chan struct{}
	flushCh   chan struct{}

	sendMu          sync.Mutex
	mu              sync.Mutex
	closed          bool
	inputPacketID   uint32
	outputPacketID  uint32
	sendQueue       map[uint32][]byte
	proxySendQueue  map[uint32][]byte
	peers           map[*proxyPeer]struct{}
	lastPeerDetach  time.Time
	lastPacketEvent time.Time
}

func newProxySession(h *proxyHub, id uint32, clientIP string, destPort uint16, tcpHost string) (*proxySession, error) {
	tcpConn, err := net.DialTimeout("tcp", tcpHost, 5*time.Second)
	if err != nil {
		return nil, err
	}

	if tcp, ok := tcpConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(60 * time.Second)
	}

	if shouldSendProxyHeader(tcpHost) {
		proxyHeader := buildPROXYv2Header(clientIP, tcpHost)
		if len(proxyHeader) == 0 {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("cannot construct PROXYv2 header")
		}
		if _, err := tcpConn.Write(proxyHeader); err != nil {
			_ = tcpConn.Close()
			return nil, err
		}
	}

	now := time.Now()
	s := &proxySession{
		hub:             h,
		id:              id,
		clientIP:        clientIP,
		destPort:        destPort,
		tcpHost:         tcpHost,
		tcpConn:         tcpConn,
		closeCh:         make(chan struct{}),
		flushCh:         make(chan struct{}, 1),
		inputPacketID:   1,
		outputPacketID:  1,
		sendQueue:       make(map[uint32][]byte),
		proxySendQueue:  make(map[uint32][]byte),
		peers:           make(map[*proxyPeer]struct{}),
		lastPeerDetach:  now,
		lastPacketEvent: now,
	}

	logMsg("Proxy", fmt.Sprintf("[session %d] established to %s", id, tcpHost))
	return s, nil
}

func (s *proxySession) start() {
	go s.tcpReadLoop()
	go s.tcpWriteLoop()
	go s.orphanWatchLoop()
}

func (s *proxySession) isClosed() bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}

func (s *proxySession) terminate(reason string) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		peers := make([]*proxyPeer, 0, len(s.peers))
		for peer := range s.peers {
			peers = append(peers, peer)
		}
		s.peers = make(map[*proxyPeer]struct{})
		s.mu.Unlock()

		close(s.closeCh)
		_ = s.tcpConn.Close()
		s.hub.remove(s.id, s)

		for _, peer := range peers {
			peer.untrackSession(s.id)
			_ = peer.sendSessionEnd(s.id)
		}

		logMsg("Proxy", fmt.Sprintf("[session %d] closed (%s)", s.id, reason))
	})
}

func (s *proxySession) addPeer(peer *proxyPeer) bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}

	s.peers[peer] = struct{}{}
	s.lastPacketEvent = time.Now()

	pendingIDs := make([]uint32, 0, len(s.proxySendQueue))
	for id := range s.proxySendQueue {
		pendingIDs = append(pendingIDs, id)
	}
	s.mu.Unlock()

	sort.Slice(pendingIDs, func(i, j int) bool { return pendingIDs[i] < pendingIDs[j] })
	for _, packetID := range pendingIDs {
		s.mu.Lock()
		payload, ok := s.proxySendQueue[packetID]
		s.mu.Unlock()
		if !ok {
			continue
		}
		if err := peer.send(payload); err != nil {
			return false
		}
	}

	return true
}

func (s *proxySession) removePeer(peer *proxyPeer) {
	s.mu.Lock()
	if _, ok := s.peers[peer]; ok {
		delete(s.peers, peer)
		if len(s.peers) == 0 {
			s.lastPeerDetach = time.Now()
		}
	}
	s.mu.Unlock()
}

func (s *proxySession) onProxyPacket(packetID uint32, lastReceivedPacketID uint32, packet []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.lastPacketEvent = time.Now()

	for id := range s.proxySendQueue {
		if id <= lastReceivedPacketID {
			delete(s.proxySendQueue, id)
		}
	}
	if packetID < s.inputPacketID {
		s.mu.Unlock()
		return
	}

	if len(s.sendQueue) >= ProxyMaxPendingPackets {
		s.mu.Unlock()
		s.terminate("input queue overflow")
		return
	}

	if _, exists := s.sendQueue[packetID]; !exists {
		payload := make([]byte, len(packet))
		copy(payload, packet)
		s.sendQueue[packetID] = payload
	}

	shouldFlush := packetID == s.inputPacketID
	s.mu.Unlock()

	if shouldFlush {
		select {
		case s.flushCh <- struct{}{}:
		default:
		}
	}
}

func (s *proxySession) tcpWriteLoop() {
	for {
		select {
		case <-s.closeCh:
			return
		case <-s.flushCh:
		}

		for {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}

			packet, ok := s.sendQueue[s.inputPacketID]
			if !ok {
				s.mu.Unlock()
				break
			}

			delete(s.sendQueue, s.inputPacketID)
			s.inputPacketID++
			s.lastPacketEvent = time.Now()
			s.mu.Unlock()

			if err := writeAll(s.tcpConn, packet); err != nil {
				s.terminate(fmt.Sprintf("tcp write error: %v", err))
				return
			}
		}
	}
}

func (s *proxySession) tcpReadLoop() {
	var header [2]byte

	for {
		if _, err := io.ReadFull(s.tcpConn, header[:]); err != nil {
			s.terminate(fmt.Sprintf("tcp read header error: %v", err))
			return
		}

		packetLen := binary.LittleEndian.Uint16(header[:])
		if packetLen == 0 {
			continue
		}

		if int(packetLen)+16 > ProxyMaxFrameSize {
			s.terminate(fmt.Sprintf("tcp packet too big: %d", packetLen))
			return
		}

		body := make([]byte, packetLen)
		if _, err := io.ReadFull(s.tcpConn, body); err != nil {
			s.terminate(fmt.Sprintf("tcp read body error: %v", err))
			return
		}

		s.sendMu.Lock()
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			s.sendMu.Unlock()
			return
		}

		packetID := s.outputPacketID
		s.outputPacketID++
		lastReceived := s.inputPacketID - 1

		frame := make([]byte, int(packetLen)+16)
		binary.LittleEndian.PutUint16(frame[0:2], uint16(packetLen+14))
		binary.LittleEndian.PutUint32(frame[2:6], s.id)
		binary.LittleEndian.PutUint32(frame[6:10], packetID)
		binary.LittleEndian.PutUint32(frame[10:14], lastReceived)
		copy(frame[14:], header[:])
		copy(frame[16:], body)

		if len(s.proxySendQueue) >= ProxyMaxPendingPackets {
			s.mu.Unlock()
			s.sendMu.Unlock()
			s.terminate("output queue overflow")
			return
		}

		s.proxySendQueue[packetID] = frame
		s.lastPacketEvent = time.Now()

		peers := make([]*proxyPeer, 0, len(s.peers))
		for peer := range s.peers {
			peers = append(peers, peer)
		}
		s.mu.Unlock()

		for _, peer := range peers {
			if err := peer.send(frame); err != nil {
				peer.close()
			}
		}
		s.sendMu.Unlock()
	}
}

func (s *proxySession) orphanWatchLoop() {
	ticker := time.NewTicker(ProxySessionCheckEvery)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}

		orphaned := len(s.peers) == 0 && time.Since(s.lastPeerDetach) > ProxySessionOrphanTTL
		s.mu.Unlock()

		if orphaned {
			s.terminate("orphan timeout")
			return
		}
	}
}

type proxyPeer struct {
	conn     *websocket.Conn
	clientIP string

	closeOnce sync.Once
	closedCh  chan struct{}

	writeMu sync.Mutex
	writeCh chan []byte

	sessionsMu sync.Mutex
	sessions   map[uint32]struct{}
}

func newProxyPeer(conn *websocket.Conn, clientIP string) *proxyPeer {
	return &proxyPeer{
		conn:     conn,
		clientIP: clientIP,
		closedCh: make(chan struct{}),
		writeCh:  make(chan []byte, ProxyPeerWriteQueueCap),
		sessions: make(map[uint32]struct{}),
	}
}

func (p *proxyPeer) trackSession(sessionID uint32) {
	p.sessionsMu.Lock()
	p.sessions[sessionID] = struct{}{}
	p.sessionsMu.Unlock()
}

func (p *proxyPeer) hasSession(id uint32) bool {
	p.sessionsMu.Lock()
	defer p.sessionsMu.Unlock()
	_, ok := p.sessions[id]
	return ok
}

func (p *proxyPeer) untrackSession(sessionID uint32) {
	p.sessionsMu.Lock()
	delete(p.sessions, sessionID)
	p.sessionsMu.Unlock()
}

func (p *proxyPeer) close() {
	p.closeWithReason("unspecified")
}

func (p *proxyPeer) closeWithReason(reason string) {
	p.closeOnce.Do(func() {
		close(p.closedCh)
		_ = p.conn.Close()

		p.sessionsMu.Lock()
		sessionIDs := make([]uint32, 0, len(p.sessions))
		for sessionID := range p.sessions {
			sessionIDs = append(sessionIDs, sessionID)
		}
		p.sessions = make(map[uint32]struct{})
		p.sessionsMu.Unlock()

		for _, sessionID := range sessionIDs {
			if session := proxyHubGlobal.get(sessionID); session != nil {
				session.removePeer(p)
			}
		}

		logMsg("Proxy", fmt.Sprintf("[peer %s] closed (%s)", p.clientIP, reason))
	})
}

func (p *proxyPeer) writeLoop() {
	for {
		select {
		case <-p.closedCh:
			return
		case packet := <-p.writeCh:
			p.writeMu.Lock()
			if err := p.conn.SetWriteDeadline(time.Now().Add(WSWriteWait)); err != nil {
				p.writeMu.Unlock()
				p.closeWithReason(fmt.Sprintf("set write deadline error: %v", err))
				return
			}
			err := p.conn.WriteMessage(websocket.BinaryMessage, packet)
			p.writeMu.Unlock()
			if err != nil {
				p.closeWithReason(fmt.Sprintf("ws write error: %v", err))
				return
			}
		}
	}
}

func (p *proxyPeer) send(packet []byte) error {
	select {
	case <-p.closedCh:
		return net.ErrClosed
	default:
	}

	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)

	select {
	case p.writeCh <- packetCopy:
		return nil
	case <-p.closedCh:
		return net.ErrClosed
	default:
		// Don't let one stuck peer block live traffic for the session.
		p.closeWithReason("peer write queue full")
		return fmt.Errorf("peer write queue full")
	}
}

func (p *proxyPeer) writeControlPing() error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(WSWriteWait))
}

func (p *proxyPeer) sendPingPacket() error {
	frame := make([]byte, 14)
	binary.LittleEndian.PutUint16(frame[0:2], ProxyFrameMinSize)
	return p.send(frame)
}

func (p *proxyPeer) sendSessionEnd(sessionID uint32) error {
	frame := make([]byte, 14)
	binary.LittleEndian.PutUint16(frame[0:2], ProxyFrameMinSize)
	binary.LittleEndian.PutUint32(frame[2:6], sessionID)
	binary.LittleEndian.PutUint32(frame[6:10], ProxySessionEndPacketID)
	return p.send(frame)
}

func (p *proxyPeer) handleFrame(payload []byte) {
	if len(payload) < ProxyFrameMinSize {
		p.closeWithReason("proxy frame too small")
		return
	}

	sessionID := binary.LittleEndian.Uint32(payload[0:4])
	packetID := binary.LittleEndian.Uint32(payload[4:8])
	lastReceivedPacketID := binary.LittleEndian.Uint32(payload[8:12])

	if sessionID == 0 {
		if err := p.sendPingPacket(); err != nil {
			p.close()
		}
		return
	}

	if packetID == ProxySessionEndPacketID {
		if session := proxyHubGlobal.get(sessionID); session != nil {
			session.removePeer(p)
		}
		p.untrackSession(sessionID)
		return
	}

	if packetID == 0 {
		p.sessionsMu.Lock()
		if len(p.sessions) >= 32 {
			p.sessionsMu.Unlock()
			p.closeWithReason("too many sessions on peer")
			return
		}
		p.sessionsMu.Unlock()
		destPort := uint16(lastReceivedPacketID & 0xFFFF)
		session, err := proxyHubGlobal.getOrCreate(sessionID, p.clientIP, destPort)
		if err != nil {
			logMsg("Proxy", fmt.Sprintf("[session %d] add failed (%s): %v", sessionID, p.clientIP, err))
			_ = p.sendSessionEnd(sessionID)
			return
		}

		p.trackSession(sessionID)
		if !session.addPeer(p) {
			_ = p.sendSessionEnd(sessionID)
			return
		}
		return
	}

	if !p.hasSession(sessionID) {
		p.closeWithReason("unregistered proxy session")
		return
	}
	session := proxyHubGlobal.get(sessionID)
	if session == nil {
		_ = p.sendSessionEnd(sessionID)
		return
	}

	if len(payload) < 14 {
		p.closeWithReason("proxy frame missing payload size")
		return
	}

	packetSize := binary.LittleEndian.Uint16(payload[12:14])
	if int(packetSize)+14 > len(payload) {
		p.closeWithReason(fmt.Sprintf("proxy payload truncated size=%d frame=%d", packetSize, len(payload)))
		return
	}

	packet := make([]byte, int(packetSize)+2)
	copy(packet, payload[12:int(packetSize)+14])
	session.onProxyPacket(packetID, lastReceivedPacketID, packet)
}

func (p *proxyPeer) readLoop() {
	defer p.close()

	reader := &wsReader{conn: p.conn}
	header := make([]byte, 2)

	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			p.closeWithReason(fmt.Sprintf("ws read header error: %v", err))
			return
		}

		packetSize := binary.LittleEndian.Uint16(header)
		if packetSize < ProxyFrameMinSize || packetSize > ProxyMaxFrameSize {
			p.closeWithReason(fmt.Sprintf("invalid proxy frame size: %d", packetSize))
			return
		}

		payload := make([]byte, packetSize)
		if _, err := io.ReadFull(reader, payload); err != nil {
			p.closeWithReason(fmt.Sprintf("ws read payload error: %v", err))
			return
		}

		p.handleFrame(payload)
	}
}

func handleProxyWebSocket() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := extractClientIP(r)
		if !allowUpgrade(r) {
			http.Error(w, "upgrade denied", http.StatusForbidden)
			return
		}
		if isIPv6(clientIP) {
			http.Error(w, "IPv6 is not supported", http.StatusForbidden)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logMsg("Error", fmt.Sprintf("Proxy WebSocket upgrade failed: %v", err))
			return
		}

		ws.EnableWriteCompression(false)
		ws.SetReadLimit(maxWSMessage())
		_ = ws.SetReadDeadline(time.Now().Add(WSPongWait))
		ws.SetPongHandler(func(string) error {
			return ws.SetReadDeadline(time.Now().Add(WSPongWait))
		})

		peer := newProxyPeer(ws, clientIP)
		go peer.writeLoop()

		go func() {
			ticker := time.NewTicker(WSPingPeriod)
			defer ticker.Stop()
			for {
				select {
				case <-peer.closedCh:
					return
				case <-ticker.C:
					if err := peer.writeControlPing(); err != nil {
						peer.closeWithReason(fmt.Sprintf("ping error: %v", err))
						return
					}
				}
			}
		}()

		peer.readLoop()
	}
}

func extractClientIP(r *http.Request) string {
	return clientIPFromTrustedRequest(r)
}

func originalExtractClientIP(r *http.Request) string {
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	clientIP := r.RemoteAddr
	if strings.Contains(clientIP, ":") {
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}
	}
	clientIP = strings.TrimPrefix(clientIP, "::ffff:")

	if clientIP == "" || clientIP == "127.0.0.1" || clientIP == "::1" {
		logMsg("Warning", fmt.Sprintf("Using localhost IP: %s", clientIP))
	}

	return clientIP
}

func isIPv6(clientIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	return ip != nil && ip.To4() == nil
}

func handleWebSocket(tcpHost string, limiter *limiterBucket) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := extractClientIP(r)
		if !allowUpgrade(r) {
			http.Error(w, "upgrade denied", http.StatusForbidden)
			return
		}
		logMsg("Server", fmt.Sprintf("[%s] New connection from: %s -> %s", limiter.cfg.name, clientIP, tcpHost))
		if isIPv6(clientIP) {
			http.Error(w, "IPv6 is not supported", http.StatusForbidden)
			return
		}

		if !limiter.allowAttempt(clientIP) {
			logMsg("RateLimit", fmt.Sprintf("[%s] Rejected recurring connection from %s", limiter.cfg.name, clientIP))
			http.Error(w, "Too many reconnect attempts", http.StatusTooManyRequests)
			return
		}

		if !limiter.incConn(clientIP) {
			logMsg("RateLimit", fmt.Sprintf("[%s] Rejected connection from %s (concurrent limit %d)", limiter.cfg.name, clientIP, limiter.cfg.maxConnPerIP))
			http.Error(w, "Too many concurrent connections", http.StatusTooManyRequests)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			limiter.decConn(clientIP)
			logMsg("Error", fmt.Sprintf("WebSocket upgrade failed: %v", err))
			return
		}

		ws.EnableWriteCompression(false)
		ws.SetReadLimit(maxWSMessage())
		_ = ws.SetReadDeadline(time.Now().Add(WSPongWait))
		ws.SetPongHandler(func(string) error {
			return ws.SetReadDeadline(time.Now().Add(WSPongWait))
		})

		bridge := NewBridge(ws, clientIP, tcpHost, limiter)
		bridge.Start()
	}
}

func logMsg(tag, message string) {
	if EnableLogging {
		log.Printf("[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05.000"), tag, message)
	}
}
