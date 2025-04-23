package utils

import (
	"errors"
	"os"
	"path"
	"time"
)

type Cache interface {
	Get(key string, maxAge time.Duration) ([]byte, error)

	Set(key string, value []byte) error
}

func CachePrefix(c Cache, prefix string) Cache {
	if c == nil {
		return nil
	}
	return prefixCache{
		c:      c,
		prefix: prefix,
	}
}

func CacheDirectory(directory string) (Cache, error) {
	if stat, err := os.Stat(directory); err != nil {
		return nil, err
	} else if !stat.IsDir() {
		return nil, errors.New("not a directory")
	}
	return dirCache(directory), nil
}

type prefixCache struct {
	c      Cache
	prefix string
}

func (c prefixCache) Get(key string, maxAge time.Duration) ([]byte, error) {
	return c.c.Get(c.prefix+key, maxAge)
}

func (c prefixCache) Set(key string, value []byte) error {
	return c.c.Set(c.prefix+key, value)
}

type dirCache string

var ErrExpired = errors.New("key expired")

func (d dirCache) Get(key string, maxAge time.Duration) ([]byte, error) {
	fname := path.Join(string(d), key)
	stat, err := os.Stat(fname)
	if err != nil {
		return nil, err
	}
	if stat.IsDir() {
		return nil, errors.New("key is directory")
	}
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	if stat.ModTime().Before(time.Now().Add(-maxAge)) {
		return data, ErrExpired
	} else {
		return data, nil
	}
}

func (d dirCache) Set(key string, value []byte) error {
	fname := path.Join(string(d), key)
	fs, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer fs.Close()
	_, err = fs.Write(value)
	fs.Sync()
	fs.Close()

	_ = os.Chtimes(fname, time.Time{}, time.Now())
	return err
}
