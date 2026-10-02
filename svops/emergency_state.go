package svops

import (
	"time"

	"github.com/codemodify/secretvault/svrpc"
)

// When says a moment of a grant's, or "-" when there is none.
func When(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// TrusteeName is who a grant is for, as people are told.
func TrusteeName(g svrpc.EmergencyGrant) string {
	if g.Trustee != "" {
		return g.Trustee
	}
	return "the trustee"
}

// GrantState says where a grant of emergency access stands, as its
// server last said.
func GrantState(g svrpc.EmergencyGrant) string {
	switch g.State {
	case svrpc.GrantInvited:
		return "not accepted yet"
	case svrpc.GrantAccepted:
		s := "accepted"
		if g.Device != "" {
			s += " on " + g.Device
		}
		if g.Denied != nil {
			s += "; last request denied " + When(g.Denied)
		}
		return s
	case svrpc.GrantRequested:
		return "REQUESTED " + When(g.Requested) + "; released " + When(g.ReleasesAt) + " unless denied"
	case svrpc.GrantReleased:
		return "RELEASED " + When(g.Released)
	}
	return "unknown to the server"
}
