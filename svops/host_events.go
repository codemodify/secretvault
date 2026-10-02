package svops

import (
	"fmt"

	"github.com/codemodify/secretvault/svrpc"
)

// HostEventColumns say a line of the host's log as people read it: who
// asked (a unit, a local service, a process), what for, and why it went
// as it did.
func HostEventColumns(ev svrpc.HostEvent) (who, what, detail string) {
	who, what, detail = ev.Program, ev.Ref, ev.Reason
	switch {
	case ev.Outcome == "changed":
		what = "the policy"
	case ev.Unit != "":
		who, what = ev.Unit, "credential "+ev.Credential
		if detail == "" {
			detail = ev.Ref
		}
	default:
		who = fmt.Sprintf("%s, uid %d", ev.Program, ev.UID)
	}
	if who == "" || ev.Unit == "" && ev.Program == "" {
		who = fmt.Sprintf("process %d (uid %d)", ev.PID, ev.UID)
	}
	return who, what, detail
}

// HostClientName says who a local service is: a user, or a program run
// by one.
func HostClientName(user, program string) string {
	if program == "" {
		return "User " + user
	}
	return program + ", run by user " + user + ","
}
