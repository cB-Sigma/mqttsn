// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
)

// MemoryBroker is an in-process publish/subscribe broker for the gateway:
// for tests, and for programs that consume MQTT-SN traffic themselves
// (Subscribe a handler). It keeps retained messages; QoS is passed
// through as given (the lower of publish and subscription).
type MemoryBroker struct {
	mu       sync.Mutex
	subs     map[*memLink]map[string]byte
	handlers []memHandler
	retained map[string]Delivery
}

type memHandler struct {
	filter string
	fn     func(Delivery)
}

type memLink struct {
	b       *MemoryBroker
	deliver func(Delivery)
}

// NewMemoryBroker makes an empty broker.
func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{subs: map[*memLink]map[string]byte{}, retained: map[string]Delivery{}}
}

// Open implements Broker.
func (b *MemoryBroker) Open(_ context.Context, _ string, _ *Will, deliver func(Delivery)) (Link, error) {
	l := &memLink{b: b, deliver: deliver}
	b.mu.Lock()
	b.subs[l] = map[string]byte{}
	b.mu.Unlock()
	return l, nil
}

// Connected implements Broker; it is always true.
func (b *MemoryBroker) Connected() bool { return true }

// Subscribe calls fn for every message matching filter (published by
// clients or by Publish).
func (b *MemoryBroker) Subscribe(filter string, fn func(Delivery)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = append(b.handlers, memHandler{filter, fn})
}

// Publish implements Broker and publishes to every subscriber.
func (b *MemoryBroker) Publish(_ context.Context, topic string, payload []byte, qos byte, retain bool) error {
	d := Delivery{Topic: topic, Payload: append([]byte(nil), payload...), QoS: qos, Retain: false}
	b.mu.Lock()
	if retain {
		if len(payload) == 0 {
			delete(b.retained, topic)
		} else {
			r := d
			r.Retain = true
			b.retained[topic] = r
		}
	}
	type target struct {
		fn  func(Delivery)
		qos byte
	}
	var ts []target
	for l, fs := range b.subs {
		best, hit := byte(0), false
		for f, q := range fs {
			if TopicMatch(f, topic) {
				hit = true
				best = max(best, q)
			}
		}
		if hit {
			ts = append(ts, target{l.deliver, min(best, qos)})
		}
	}
	for _, h := range b.handlers {
		if TopicMatch(h.filter, topic) {
			ts = append(ts, target{h.fn, qos})
		}
	}
	b.mu.Unlock()
	for _, t := range ts {
		x := d
		x.QoS = t.qos
		t.fn(x)
	}
	return nil
}

func (l *memLink) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	return l.b.Publish(ctx, topic, payload, qos, retain)
}

func (l *memLink) Subscribe(_ context.Context, filter string, qos byte) error {
	b := l.b
	b.mu.Lock()
	if fs := b.subs[l]; fs != nil {
		fs[filter] = qos
	}
	var rs []Delivery
	for t, r := range b.retained {
		if TopicMatch(filter, t) {
			r.QoS = min(r.QoS, qos)
			rs = append(rs, r)
		}
	}
	b.mu.Unlock()
	for _, r := range rs {
		l.deliver(r)
	}
	return nil
}

func (l *memLink) Unsubscribe(_ context.Context, filter string) error {
	l.b.mu.Lock()
	defer l.b.mu.Unlock()
	delete(l.b.subs[l], filter)
	return nil
}

func (l *memLink) Close() {
	l.b.mu.Lock()
	defer l.b.mu.Unlock()
	delete(l.b.subs, l)
}
