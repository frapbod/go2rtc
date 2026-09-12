package hap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/AlexxIT/go2rtc/pkg/hap/chacha20poly1305"
)

func testReadConn(data []byte) *Conn {
	return &Conn{rw: bufio.NewReadWriter(bufio.NewReader(bytes.NewReader(data)), bufio.NewWriter(io.Discard)), decryptKey: make([]byte, 32)}
}

func testEncryptedFrame(t *testing.T, plain []byte) []byte {
	t.Helper()
	header := make([]byte, 2)
	binary.LittleEndian.PutUint16(header, uint16(len(plain)))
	encrypted, err := chacha20poly1305.EncryptAndSeal(make([]byte, 32), nil, make([]byte, 8), plain, header)
	if err != nil {
		t.Fatal(err)
	}
	return append(header, encrypted...)
}

func TestConnReadRejectsInvalidFramesWithoutReportingPlaintext(t *testing.T) {
	valid := testEncryptedFrame(t, []byte("private response"))
	corrupt := append([]byte(nil), valid...)
	corrupt[len(corrupt)-1] ^= 1
	for name, data := range map[string][]byte{
		"plaintext HTTP after rejected pairing": []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		"oversized encrypted frame":             {1, 4},
		"truncated header":                      {4},
		"truncated payload":                     valid[:len(valid)-1],
		"failed authentication":                 corrupt,
	} {
		t.Run(name, func(t *testing.T) {
			c := testReadConn(data)
			n, err := c.Read(make([]byte, 4096))
			if n != 0 || err == nil {
				t.Fatalf("Read=(%d,%v), want zero bytes and error", n, err)
			}
			if c.recv != 0 || c.decryptCnt != 0 {
				t.Fatal("failed frame advanced accepted data counters")
			}
		})
	}
}

func TestConnReadHonorsSmallBuffers(t *testing.T) {
	plain := bytes.Repeat([]byte("0123456789"), 100)
	for _, size := range []int{1, 7, 1024, 4096} {
		c := testReadConn(testEncryptedFrame(t, plain))
		var got []byte
		buf := make([]byte, size)
		for len(got) < len(plain) {
			n, err := c.Read(buf)
			if err != nil || n <= 0 || n > len(buf) {
				t.Fatalf("size=%d Read=(%d,%v)", size, n, err)
			}
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got, plain) {
			t.Fatal("decrypted bytes differ")
		}
		if c.recv != len(plain) || c.decryptCnt != 1 {
			t.Fatal("one frame must count exactly once")
		}
	}
}
