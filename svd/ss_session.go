package svd

import "github.com/codemodify/secretvault/svsecret"

// Secret Service sessions: how secrets cross the bus (see svsecret for the
// algorithms).

const (
	algPlain = svsecret.Plain
	algDH    = svsecret.DH
)

// ssSession is one open Secret Service session.
type ssSession struct {
	owner string // the sender that opened it
	key   []byte // AES-128 key; nil for plain
}

// dhSession answers a client's DH public key with ours and the session key.
func dhSession(clientPub []byte) (serverPub, key []byte, err error) {
	k := svsecret.NewDHKey()
	key, err = k.SessionKey(clientPub)
	return k.Pub, key, err
}

func (s *ssSession) seal(secret []byte) (params, value []byte, err error) {
	return svsecret.SealSecret(s.key, secret)
}

func (s *ssSession) open(params, value []byte) ([]byte, error) {
	return svsecret.OpenSecret(s.key, params, value)
}
