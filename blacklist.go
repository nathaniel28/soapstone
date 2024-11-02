package main

import (
	"bufio"
	"sync"
	"os"
)

type Blacklist struct {
	table sync.Map
}

func (b *Blacklist) Present(key string) bool {
	_, found := b.table.Load(key)
	return found
}

func (b *Blacklist) Insert(key string) {
	b.table.Store(key, struct{}{})
}

func (b *Blacklist) Erase(key string) {
	b.table.Delete(key)
}

func (b *Blacklist) FromFile(path string) error {
	fp, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	s := bufio.NewScanner(fp)
	for s.Scan() {
		b.Insert(s.Text())
	}
	fp.Close()
	return nil
}

func (b *Blacklist) ToFile(path string) error {
	// I'm so tired I forgot if O_CREAT implies O_TRUNC
	fp, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	b.table.Range(func(key, _ any) bool {
		fp.WriteString(key.(string))
		fp.Write([]byte{'\n'})
		return true
	})
	fp.Close()
	return nil
}
