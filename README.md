go-nflog [![GoDoc](https://godoc.org/github.com/florianl/go-nflog?status.svg)](https://godoc.org/github.com/florianl/go-nflog)
============

This is `go-nflog` and it is written in [golang](https://golang.org/). It provides a [C](https://en.wikipedia.org/wiki/C_(programming_language))-binding free API to the netfilter based log subsystem of the [Linux kernel](https://www.kernel.org).

Example
-------

```golang
func main() {
	// Send outgoing pings to nflog group 100
	// # sudo iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100

	nf, err := nflog.Open()
	if err != nil {
		fmt.Println("could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(m nflog.Msg) int {
		ts, err := m.Timestamp()
		if err != nflog.ErrNoTimestamp {
			ts = time.Now()
		}
		fmt.Printf("%s\t%v\n", ts, m[nflog.NfUlaAttrPayload])
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, unix.AF_INET, 100, nflog.NfUlnlCopyPacket, fn)
	if err != nil {
		fmt.Println(err)
		return
	}

	select {
	// Block till the context expires
	case <-ctx.Done():
	}
}
```


For documentation and more examples please take a look at [![GoDoc](https://godoc.org/github.com/florianl/go-nflog?status.svg)](https://godoc.org/github.com/florianl/go-nflog)