// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"

	"github.com/cB-Sigma/mqttsn"
	"github.com/cB-Sigma/mqttsn/client"
	"github.com/cB-Sigma/mqttsn/dtls"
	"github.com/cB-Sigma/mqttsn/gateway"
)

const bisquittImage = "sigma-mqttsn-bisquitt:0.9.1"

func needBisquitt(t *testing.T) {
	t.Helper()
	needDocker(t)
	if exec.Command("docker", "image", "inspect", bisquittImage).Run() == nil {
		return
	}
	if out, err := exec.Command("docker", "build", "-q", "-t", bisquittImage, "bisquitt").CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

func dtlsConfig(t *testing.T) *dtls.Config {
	t.Helper()
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	return &dtls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
}

// served starts this module's gateway with an in-memory broker on every
// interface, over UDP or DTLS.
func served(t *testing.T, useDTLS bool) (*gateway.MemoryBroker, int, *bufSeen) {
	t.Helper()
	port := freePort(t, "udp")
	var pc net.PacketConn
	var err error
	if useDTLS {
		pc, err = dtls.Listen(fmt.Sprintf("0.0.0.0:%d", port), dtlsConfig(t))
	} else {
		pc, err = net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", port))
	}
	if err != nil {
		t.Fatal(err)
	}
	b := gateway.NewMemoryBroker()
	s := &bufSeen{}
	b.Subscribe("#", func(d gateway.Delivery) { s.add(d.Topic + " " + string(d.Payload)) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = gateway.New(b, gateway.Options{}).Serve(ctx, pc); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return b, port, s
}

type bufSeen struct {
	mu    sync.Mutex
	lines []string
}

func (s *bufSeen) add(l string) { s.mu.Lock(); s.lines = append(s.lines, l); s.mu.Unlock() }
func (s *bufSeen) has(l string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.lines {
		if x == l {
			return true
		}
	}
	return false
}

// TestBisquittClientsAgainstGateway: bisquitt-pub publishes at QoS 0 and
// 1 and bisquitt-sub receives a message, through this module's gateway,
// over UDP and over DTLS 1.2 (self-signed certificates).
// Covers: SIG-IPE-6722, SIG-IPE-6723
func TestBisquittClientsAgainstGateway(t *testing.T) {
	needBisquitt(t)
	host := hostIPv4(t)
	for _, useDTLS := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "dtls"}[useDTLS], func(t *testing.T) {
			b, port, s := served(t, useDTLS)
			sec := []string{}
			if useDTLS {
				sec = []string{"--dtls", "--self-signed", "--insecure"}
			}
			for _, q := range []string{"0", "1"} {
				args := append([]string{"run", "--rm", "--add-host=host.docker.internal:host-gateway", bisquittImage,
					"timeout", "15", "bisquitt-pub", "--host", host, "--port", fmt.Sprint(port)}, sec...)
				args = append(args, "--topic", "sigma/bq", "--message", "q"+q, "--qos", q, "--client-id", "bqpub"+q)
				out, err := exec.Command("docker", args...).CombinedOutput()
				deadline := time.Now().Add(5 * time.Second)
				for !s.has("sigma/bq q"+q) && time.Now().Before(deadline) {
					time.Sleep(50 * time.Millisecond)
				}
				if !s.has("sigma/bq q" + q) {
					t.Errorf("QoS %s publish of bisquitt-pub did not arrive (%v):\n%s", q, err, out)
				}
			}
			args := append([]string{"run", "--rm", "--add-host=host.docker.internal:host-gateway", bisquittImage,
				"timeout", "8", "bisquitt-sub", "--host", host, "--port", fmt.Sprint(port)}, sec...)
			args = append(args, "--topic", "sigma/cmd", "--qos", "1", "--client-id", "bqsub")
			cmd := exec.Command("docker", args...)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 12; i++ {
				time.Sleep(500 * time.Millisecond)
				_ = b.Publish(context.Background(), "sigma/cmd", []byte("to-bisquitt"), 1, false)
			}
			_ = cmd.Wait()
			if !strings.Contains(out.String(), "to-bisquitt") {
				t.Errorf("bisquitt-sub did not receive:\n%s", out.String())
			}
		})
	}
}

// TestClientAgainstBisquittGateway: this module's client connects to the
// bisquitt gateway (with Mosquitto behind it) over UDP and over DTLS 1.2,
// registers a topic, publishes at QoS 1 and 2, and subscribes and
// receives a message published on the broker.
// Covers: SIG-IPE-6723
func TestClientAgainstBisquittGateway(t *testing.T) {
	needBisquitt(t)
	for _, useDTLS := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "dtls"}[useDTLS], func(t *testing.T) {
			port := freePort(t, "udp")
			name := fmt.Sprintf("sigma-bisquitt-%d", time.Now().UnixNano())
			args := []string{"run", "-d", "--rm", "--name", name, "-p", fmt.Sprintf("127.0.0.1:%d:1884/udp", port), bisquittImage, "gateway"}
			if useDTLS {
				args = append(args, "--dtls", "--self-signed", "--insecure")
			}
			if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
				t.Fatalf("docker run: %v\n%s", err, out)
			}
			t.Cleanup(func() {
				if t.Failed() {
					logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
					t.Logf("bisquitt:\n%s", logs)
				}
				_ = exec.Command("docker", "rm", "-f", name).Run()
			})
			time.Sleep(2 * time.Second)
			sub := exec.Command("docker", "exec", name, "mosquitto_sub", "-h", "127.0.0.1", "-t", "sigma/#", "-v", "-C", "2", "-W", "20")
			var subOut bytes.Buffer
			sub.Stdout, sub.Stderr = &subOut, &subOut
			if err := sub.Start(); err != nil {
				t.Fatal(err)
			}
			time.Sleep(700 * time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			var c *client.Client
			if useDTLS {
				conn, err := dtls.Dial(ctx, addr, dtlsConfig(t))
				if err != nil {
					t.Fatal(err)
				}
				c = client.New(conn, "sigmadev", client.Options{})
			} else {
				var err error
				if c, err = client.Dial(addr, "sigmadev"); err != nil {
					t.Fatal(err)
				}
			}
			defer c.Close()
			if err := c.Connect(ctx, 30*time.Second, true, nil); err != nil {
				t.Fatal(err)
			}
			id, err := c.Register(ctx, "sigma/temp")
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Publish(ctx, mqttsn.TopicNormal, id, 1, false, []byte("q1")); err != nil {
				t.Fatal(err)
			}
			if err := c.Publish(ctx, mqttsn.TopicNormal, id, 2, false, []byte("q2")); err != nil {
				t.Fatal(err)
			}
			_ = sub.Wait()
			for _, want := range []string{"sigma/temp q1", "sigma/temp q2"} {
				if !strings.Contains(subOut.String(), want) {
					t.Errorf("broker did not get %q:\n%s", want, subOut.String())
				}
			}
			if _, _, err := c.Subscribe(ctx, mqttsn.TopicNormal, "sigma/cmd", 0, 1); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("docker", "exec", name, "mosquitto_pub", "-h", "127.0.0.1", "-t", "sigma/cmd", "-m", "on", "-q", "1").CombinedOutput(); err != nil {
				t.Fatalf("mosquitto_pub: %v %s", err, out)
			}
			select {
			case d := <-c.Messages():
				if d.Topic != "sigma/cmd" || string(d.Data) != "on" {
					t.Errorf("delivery %+v", d)
				}
			case <-time.After(10 * time.Second):
				t.Error("no delivery from the bisquitt gateway")
			}
			_ = c.Disconnect(ctx)
		})
	}
}
