package hap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResolvedAddressSkipsDiscoveryButStillVerifiesPairing(t *testing.T) {
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		requests <- r.URL.Path
		w.Header().Set("Content-Type", MimeTLV8)
		// Deliberately invalid peer state: resolving an address cannot bypass auth.
		w.Write([]byte{6, 1, 4})
	}))
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		c, err := Dial("homekit://stale.invalid:1?client_id=fixture&client_private="+strings.Repeat("00", 64),
			WithResolvedAddress(strings.TrimPrefix(server.URL, "http://")))
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("invalid peer unexpectedly passed pair verification")
		}
	case <-time.After(time.Second):
		t.Fatal("resolved local endpoint waited for discovery")
	}
	select {
	case path := <-requests:
		if path != PathPairVerify {
			t.Fatalf("request path = %q", path)
		}
	default:
		t.Fatal("resolved endpoint did not receive pair verification")
	}
}
