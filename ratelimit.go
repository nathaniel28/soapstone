package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type Limiter struct {
	hot        sync.Map
	count      atomic.Int32
	MaxEntries int32
	Burst      uint32
	Reset      time.Duration
}

func (l *Limiter) Unblock(k string) {
	l.hot.Delete(k)
	l.count.Add(-1)
}

func (l *Limiter) Block(k string) bool {
	c := l.count.Load()
	if c > l.MaxEntries {
		return true
	}
	res, loaded := l.hot.LoadOrStore(k, uint32(1))
	if loaded {
		v := res.(uint32)
		if v >= l.Burst {
			return true
		}
		l.hot.Store(k, v+1)
	} else {
		l.count.Add(1)
		go func(l_ *Limiter, k_ string) {
			time.Sleep(l_.Reset)
			l_.Unblock(k_)
		}(l, k)
	}
	return false
}
