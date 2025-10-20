
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var sign_counter atomic.Uint64
var verify_counter atomic.Uint64

func sign(ctx context.Context, wg *sync.WaitGroup) {
	defer func() { wg.Done() }()

	priv, err := ecdsa.GenerateKey(elliptic.SM2(), rand.Reader)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	_, ok := priv.Public().(*ecdsa.PublicKey)
	if !ok {
		fmt.Printf("Not an SM2 private key\n")
		return
	}

	msg := []byte("hello, world! just aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ttttttttttttttttttttttteeeeeeeeeeeeeeessssssssssssssttttttttttttttttttttttttttttt")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, _, err := ecdsa.Sign(rand.Reader, priv, msg)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		sign_counter.Add(1)
	}
}

func verify(ctx context.Context, wg *sync.WaitGroup) {
	defer func() { wg.Done() }()

	priv, err := ecdsa.GenerateKey(elliptic.SM2(), rand.Reader)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	pub, ok := priv.Public().(*ecdsa.PublicKey)
	if !ok {
		fmt.Printf("Not an SM2 private key\n")
		return
	}

	msg := []byte("hello, world! just aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ttttttttttttttttttttttteeeeeeeeeeeeeeessssssssssssssttttttttttttttttttttttttttttt")
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !ecdsa.Verify(pub, msg, r, s) {
			fmt.Printf("BUG: verify failed\n")
			return
		}

		verify_counter.Add(1)
	}
}

func progress(ctx context.Context, wg *sync.WaitGroup) {
	defer func() { wg.Done() }()

	ticker := time.NewTicker(time.Second)
	var elapse uint64

	for {
		select {
		case <-ticker.C:
			elapse++
			fmt.Printf("sign/verify: %d/%d\n", sign_counter.Load()/elapse, verify_counter.Load()/elapse)
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go sign(ctx, &wg)
	wg.Add(1)
	go verify(ctx, &wg)
	wg.Add(1)
	go progress(ctx, &wg)

	signal.Ignore(syscall.SIGHUP)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("Receive signal: %v, exiting ...\n", <-sig)

	cancel()

	wg.Wait()
}
