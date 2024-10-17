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
	req, err := AcceptSocksRequest(remoteConn)
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
	req, err := AcceptSocksRequest(remoteConn)
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

func Test_S5Request_RW(t *testing.T) {
	// IPV4
	//+------+-------+-------+------+-------------+----------+
	//| VER  |  CMD  |  RSV  | ATYP |   DST.ADDR  | DST.PORT |
	//+------+-------+-------+------+-------------+----------+
	//| 0x05 |  0x01 | 0x00  | 0x01 | 192.168.0.1 |   8080   |
	//+------+-------+-------+------+-------------+----------+
	{
		original := []byte{
			0x05, 0x01, 0x00,
			Ipv4Address, 192, 168, 1, 1,
			0x1f, 0x90,
		}
		reader := bytes.NewReader(original)
		req, err := AcceptSocksRequest(reader)
		if err != nil {
			t.Fatalf(err.Error())
		}
		//t.Logf("Request : %v", req)
		if req.Version != 0x05 {
			t.Fatalf("bad version : %d request : %v", req.Version, req)
		}
		if !bytes.Equal(req.DestAddr.IP.To4(), []byte{192, 168, 1, 1}) {
			t.Fatalf("bad destAddr : %v request : %v", req.DestAddr.IP.To4(), req)
		}
		if req.DestAddr.Port != 8080 {
			t.Fatalf("bad destAddr port : %d request : %v", req.DestAddr.Port, req)
		}

		var outBuff bytes.Buffer
		req.WriteTo(&outBuff)

		if !bytes.Equal(outBuff.Bytes(), original) {
			t.Fatalf("bad: %v %v", outBuff.Bytes(), original)
		}
	}

	// IPV4
	//+------+-------+-------+------+---------------+----------+
	//| VER  |  CMD  |  RSV  | ATYP |    DST.ADDR   | DST.PORT |
	//+------+-------+-------+------+---------------+----------+
	//| 0x05 |  0x01 | 0x00  | 0x04 | (0x00 ~ 0x0F) |   8080   |
	//+------+-------+-------+------+---------------+----------+
	{
		original := []byte{
			0x05, 0x01, 0x00,
			Ipv6Address, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x1f, 0x90,
		}
		reader := bytes.NewReader(original)
		req, err := AcceptSocksRequest(reader)
		if err != nil {
			t.Fatalf(err.Error())
		}
		//t.Logf("Request : %v", req)
		if req.Version != 0x05 {
			t.Fatalf("bad version : %d request : %v", req.Version, req)
		}
		if !bytes.Equal(req.DestAddr.IP.To16(), []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}) {
			t.Fatalf("bad destAddr : %v request : %v", req.DestAddr.IP.To16(), req)
		}
		if req.DestAddr.Port != 8080 {
			t.Fatalf("bad destAddr port : %d request : %v", req.DestAddr.Port, req)
		}

		var outBuff bytes.Buffer
		req.WriteTo(&outBuff)

		if !bytes.Equal(outBuff.Bytes(), original) {
			t.Fatalf("bad: %v %v", outBuff.Bytes(), original)
		}
	}

	// FQDN
	//+------+-------+-------+------+---------------+----------+
	//| VER  |  CMD  |  RSV  | ATYP |    DST.ADDR   | DST.PORT |
	//+------+-------+-------+------+---------------+----------+
	//| 0x05 |  0x01 | 0x00  | 0x03 | "www.goo..."  |   8080   |
	//+------+-------+-------+------+---------------+----------+
	{
		fqdn := []byte("www.google.com")
		original := []byte{
			0x05, 0x01, 0x00, FqdnAddress, uint8(len(fqdn)),
		}
		original = append(original, fqdn...)
		original = append(original, 0x1f, 0x90)

		reader := bytes.NewReader(original)
		req, err := AcceptSocksRequest(reader)
		if err != nil {
			t.Fatalf(err.Error())
		}
		//t.Logf("Request : %v", req)
		if req.Version != 0x05 {
			t.Fatalf("bad version : %d request : %v", req.Version, req)
		}
		if req.DestAddr.FQDN != "www.google.com" {
			t.Fatalf("bad destAddr : %s request : %v", req.DestAddr.FQDN, req)
		}
		if req.DestAddr.Port != 8080 {
			t.Fatalf("bad destAddr port : %d request : %v", req.DestAddr.Port, req)
		}

		var outBuff bytes.Buffer
		req.WriteTo(&outBuff)

		if !bytes.Equal(outBuff.Bytes(), original) {
			t.Fatalf("bad: %v %v", outBuff.Bytes(), original)
		}
	}

}
