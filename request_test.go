package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func createMockConn() (*MockConn, *MockConn) {
	var forwardBuf bytes.Buffer
	var backwardBuf bytes.Buffer
	return &MockConn{&forwardBuf, &backwardBuf}, &MockConn{&backwardBuf, &forwardBuf}
}

type MockConn struct {
	sendBuf    *bytes.Buffer
	receiveBuf *bytes.Buffer
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return m.receiveBuf.Read(b)
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.sendBuf.Write(b)
}

func (m *MockConn) Close() error {
	return nil
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func (m *MockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65431}
}

func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestRequest_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	localConn, remoteConn := createMockConn()

	// Create the connect request
	//buf := bytes.NewBuffer(nil)
	//buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})
	localConn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	//buf.Write(port)
	localConn.Write(port)

	// Send a ping
	//buf.Write([]byte("ping"))
	localConn.Write([]byte("ping"))

	t.Logf("localConn send buffer : %v", localConn.sendBuf.Bytes())

	// Handle the request
	//resp := &MockConn{}
	req, err := NewRequest(remoteConn)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	t.Logf("localConn send buffer (after New Request) : %v", localConn.sendBuf.Bytes())

	if err := s.handleRequest(req, remoteConn); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	var out = localConn.receiveBuf.Bytes()
	t.Logf("localConn recieve buffer (after New Request) : %v", out)
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	localConn, remoteConn := createMockConn()

	// Create the connect request
	//buf := bytes.NewBuffer(nil)
	//buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})
	localConn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	//buf.Write(port)
	localConn.Write(port)

	// Send a ping
	//buf.Write([]byte("ping"))
	localConn.Write([]byte("ping"))

	// Handle the request
	//resp := &MockConn{}
	req, err := NewRequest(remoteConn)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, remoteConn); !strings.Contains(err.Error(), "blocked by rules") {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	//out := resp.buf.Bytes()
	out := localConn.receiveBuf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
		0, 0, 0, 0,
		0, 0,
	}

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}
