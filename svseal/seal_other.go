//go:build !linux && !windows && !darwin

package svseal

type none struct{}

func platform() Sealer { return none{} }

func (none) Name() string                          { return "none" }
func (none) Available() error                      { return ErrUnavailable }
func (none) Seal(string, []byte) ([]byte, error)   { return nil, ErrUnavailable }
func (none) Unseal(string, []byte) ([]byte, error) { return nil, ErrUnavailable }
