package hap

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/hap/chacha20poly1305"
	"github.com/AlexxIT/go2rtc/pkg/hap/hkdf"
)

type Conn struct {
	conn    net.Conn
	rw      *bufio.ReadWriter
	wmu     sync.Mutex
	rmu     sync.Mutex
	readBuf []byte

	encryptKey []byte
	decryptKey []byte
	encryptCnt uint64
	decryptCnt uint64

	//ClientID  string
	SharedKey []byte

	recv int
	send int
}

func (c *Conn) MarshalJSON() ([]byte, error) {
	conn := core.Connection{
		ID:         core.ID(c),
		FormatName: "homekit",
		Protocol:   "hap",
		RemoteAddr: c.conn.RemoteAddr().String(),
		Recv:       c.recv,
		Send:       c.send,
	}
	return json.Marshal(conn)
}

func NewConn(conn net.Conn, rw *bufio.ReadWriter, sharedKey []byte, isClient bool) (*Conn, error) {
	key1, err := hkdf.Sha512(sharedKey, "Control-Salt", "Control-Read-Encryption-Key")
	if err != nil {
		return nil, err
	}

	key2, err := hkdf.Sha512(sharedKey, "Control-Salt", "Control-Write-Encryption-Key")
	if err != nil {
		return nil, err
	}

	c := &Conn{
		conn: conn,
		rw:   rw,

		SharedKey: sharedKey,
	}

	if isClient {
		c.encryptKey, c.decryptKey = key2, key1
	} else {
		c.encryptKey, c.decryptKey = key1, key2
	}

	return c, nil
}

const (
	// packetSizeMax is the max length of encrypted packets
	packetSizeMax = 0x400

	VerifySize = 2
	NonceSize  = 8
	Overhead   = 16 // chacha20poly1305.Overhead
)

func (c *Conn) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	verify := make([]byte, VerifySize) // verify = plain message size
	if _, err = io.ReadFull(c.rw, verify); err != nil {
		return
	}

	size := int(binary.LittleEndian.Uint16(verify))
	if size > packetSizeMax {
		return 0, errors.New("hap: encrypted frame exceeds maximum size")
	}

	ciphertext := make([]byte, size+Overhead)
	if _, err = io.ReadFull(c.rw, ciphertext); err != nil {
		return 0, err
	}

	nonce := make([]byte, NonceSize)
	binary.LittleEndian.PutUint64(nonce, c.decryptCnt)
	plain, err := chacha20poly1305.DecryptAndVerify(c.decryptKey, nil, nonce, ciphertext, verify)
	if err != nil {
		return 0, err
	}
	c.decryptCnt++
	c.recv += len(plain)
	n = copy(b, plain)
	c.readBuf = plain[n:]
	return n, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	buf := make([]byte, 0, packetSizeMax+Overhead)
	nonce := make([]byte, NonceSize)
	verify := make([]byte, VerifySize)

	for len(b) > 0 {
		size := len(b)
		if size > packetSizeMax {
			size = packetSizeMax
		}

		binary.LittleEndian.PutUint16(verify, uint16(size))
		if _, err = c.rw.Write(verify); err != nil {
			return
		}

		binary.LittleEndian.PutUint64(nonce, c.encryptCnt)
		c.encryptCnt++

		_, err = chacha20poly1305.EncryptAndSeal(c.encryptKey, buf, nonce, b[:size], verify)
		if err != nil {
			return
		}

		if _, err = c.rw.Write(buf[:size+Overhead]); err != nil {
			return
		}

		b = b[size:]
		n += size
	}

	err = c.rw.Flush()

	c.send += n
	return
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
