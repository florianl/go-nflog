//+build go1.12,linux

package nflog

import "time"

func (nflog *Nflog) setReadTimeout() {
	if nflog.readTimeout != 0 {
		deadline := time.Now().Add(nflog.readTimeout)
		nflog.Con.SetReadDeadline(deadline)
	}
}
