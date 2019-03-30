//+build !go1.12,linux

package nflog

func (nflog *Nflog) setReadTimeout() {
	// this feature is not available for Go version lower than 1.12
}