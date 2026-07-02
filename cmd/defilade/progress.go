package main

import (
	"io"
	"os"
	"sync"
	"time"
)

func startSpinner(w io.Writer, interval time.Duration) func() {
	done := make(chan struct{})
	var wg sync.WaitGroup
	var once sync.Once
	frames := []byte{'|', '/', '-', '\\'}

	fmtFrame := func(frame byte) { _, _ = w.Write([]byte{'\r', frame}) }
	fmtFrame(frames[0])
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for i := 1; ; i++ {
			select {
			case <-ticker.C:
				fmtFrame(frames[i%len(frames)])
			case <-done:
				return
			}
		}
	}()

	return func() {
		once.Do(func() {
			close(done)
			wg.Wait()
			_, _ = io.WriteString(w, "\r \r")
		})
	}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
