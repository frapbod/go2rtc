package hap

import (
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AlexxIT/go2rtc/pkg/hap/chacha20poly1305"
	"github.com/AlexxIT/go2rtc/pkg/hap/curve25519"
	"github.com/AlexxIT/go2rtc/pkg/hap/hkdf"
	"github.com/AlexxIT/go2rtc/pkg/hap/tlv8"
)

func TestPairVerifyRejectsM4AuthenticationError(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "accepted"
		if reject {
			name = "rejected"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", MimeTLV8)
				if calls.Add(1) == 2 {
					io.Copy(io.Discard, r.Body)
					body := []byte{6, 1, 4}
					if reject {
						body = append(body, 7, 1, 2)
					}
					w.Write(body)
					return
				}
				var m1 struct {
					PublicKey string `tlv8:"3"`
					State     byte   `tlv8:"6"`
				}
				if err := tlv8.UnmarshalReader(r.Body, r.ContentLength, &m1); err != nil {
					t.Error(err)
					return
				}
				public, private := curve25519.GenerateKeyPair()
				shared, err := curve25519.SharedSecret(private, []byte(m1.PublicKey))
				if err != nil {
					t.Error(err)
					return
				}
				key, err := hkdf.Sha512(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
				if err != nil {
					t.Error(err)
					return
				}
				inner, err := tlv8.Marshal(struct {
					Identifier string `tlv8:"1"`
				}{"fixture"})
				if err != nil {
					t.Error(err)
					return
				}
				encrypted, err := chacha20poly1305.Encrypt(key, "PV-Msg02", inner)
				if err != nil {
					t.Error(err)
					return
				}
				body, err := tlv8.Marshal(struct {
					PublicKey     string `tlv8:"3"`
					EncryptedData string `tlv8:"5"`
					State         byte   `tlv8:"6"`
				}{string(public), string(encrypted), StateM2})
				if err != nil {
					t.Error(err)
					return
				}
				w.Write(body)
			}))
			defer server.Close()
			_, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			c, err := Dial("homekit://"+strings.TrimPrefix(server.URL, "http://")+"?client_id=fixture&client_private="+hex.EncodeToString(private), WithResolvedAddress(strings.TrimPrefix(server.URL, "http://")))
			if c != nil {
				defer c.Close()
			}
			if reject && err == nil {
				t.Fatal("accessory rejected controller but Dial reported authenticated connection")
			}
			if !reject && err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatalf("handshake HTTP requests=%d, want 2", calls.Load())
			}
		})
	}
}
