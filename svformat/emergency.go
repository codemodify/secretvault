package svformat

// Emergency access (docs/format.md, "emergency slots"): a person the
// owner trusts can open the vault after a waiting period the owner can
// cut short by refusing, which a sync server keeps.
//
// An emergency keyslot needs two things to open: the trustee's identity,
// and a random 32-byte release key. The owner's device seals the master
// key under both,
//
//	wrapped = SealTo(trustee, Seal(Derive(release key, vault id, "sv1 emergency kek", 32), VMK, slot_aad), info = slot_aad)
//
// and hands the release key to the server only sealed to the trustee
// (EmergencyReleaseInfo), so the server holds nothing that opens
// anything. The server gives that sealed release key to the trustee once
// the wait is over and no one refused. The trustee's identity alone opens
// only the outer layer; the release key alone opens nothing.

// Emergency is what an emergency keyslot records about its grant.
type Emergency struct {
	// Grant names the grant on the sync server that escrows the release
	// key: 16 random bytes, made by the owner's device.
	Grant ID `json:"grant"`
}

// EmergencyKEKLabel names the key, derived from the release key, that
// seals the master key inside an emergency slot's outer layer.
const EmergencyKEKLabel = "sv1 emergency kek"

// ReleaseKeySize is the size of an emergency grant's release key.
const ReleaseKeySize = 32

// EmergencyReleaseInfo binds a release key, sealed to the trustee for the
// server to escrow, to its vault and grant:
//
//	"secretvault sv1 emergency release" || vault id || grant id
func EmergencyReleaseInfo(vault, grant ID) []byte {
	b := append([]byte("secretvault sv1 emergency release"), vault[:]...)
	return append(b, grant[:]...)
}

// EmergencyChallengeInfo binds the one-time code a trustee's device
// proves its identity with, when it accepts a grant, to the grant:
//
//	"secretvault sv1 emergency challenge" || grant id
func EmergencyChallengeInfo(grant ID) []byte {
	return append([]byte("secretvault sv1 emergency challenge"), grant[:]...)
}
