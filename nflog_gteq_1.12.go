//+build go1.12,linux

package nflog

import "time"

func (nflog *Nflog) setReadTimeout() {
	deadline := time.Now().Add(nflog.readTimeout)
	nflog.Con.SetReadDeadline(deadline)
}
