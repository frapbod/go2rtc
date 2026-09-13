package srtp

import (
	"github.com/pion/rtcp"
	"testing"
)

func TestReceiverReportBeforeSessionInitialization(t *testing.T) {
	session := &Session{}
	if _, err := session.WriteRTCP(&rtcp.ReceiverReport{}); err == nil {
		t.Fatal("uninitialized session must return an error")
	}
}
