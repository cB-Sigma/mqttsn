// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop runs this module's gateway against independent MQTT-SN
// and MQTT implementations in Docker: the Eclipse Paho MQTT-SN sample
// clients (github.com/eclipse/paho.mqtt-sn.embedded-c at e1e1b73) as
// devices and Mosquitto 2.0 as the broker. It is skipped unless
// SIGMA_MQTTSN_INTEROP=1 is set and Docker is running.
package interop

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/mqttsn/gateway"
	"github.com/cB-Sigma/mqttsn/gateway/mqttbroker"
)

const image = "sigma-mqttsn-gw-interop:paho-e1e1b73"

func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("SIGMA_MQTTSN_INTEROP") != "1" {
		t.Skip("set SIGMA_MQTTSN_INTEROP=1 to run the interop tests (needs Docker)")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	if exec.Command("docker", "image", "inspect", image).Run() == nil {
		return
	}
	if out, err := exec.Command("docker", "build", "-q", "-t", image, "peer").CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "tcp" {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// mosquitto runs the broker and returns its URL on the host and the
// container's name.
func mosquitto(t *testing.T) (string, string) {
	t.Helper()
	port := freePort(t, "tcp")
	name := fmt.Sprintf("sigma-mqttsn-broker-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "-p", fmt.Sprintf("127.0.0.1:%d:1883", port), image, "broker").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	deadline := time.Now().Add(20 * time.Second)
	for {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mosquitto did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	return fmt.Sprintf("mqtt://127.0.0.1:%d", port), name
}

func hostIPv4(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
		image, "getent", "ahostsv4", "host.docker.internal").CombinedOutput()
	if f := strings.Fields(string(out)); err == nil && len(f) > 0 {
		return f[0]
	}
	t.Fatalf("host address: %v %s", err, out)
	return ""
}

func runPaho(t *testing.T, host string, port int, sample string, secs int) string {
	t.Helper()
	out, _ := exec.Command("docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
		image, "timeout", fmt.Sprint(secs), "stdbuf", "-oL", sample, host, fmt.Sprint(port)).CombinedOutput()
	return string(out)
}

// watcher is mosquitto_sub inside the broker container.
type watcher struct {
	mu  sync.Mutex
	out bytes.Buffer
	cmd *exec.Cmd
}

func watch(t *testing.T, container string) *watcher {
	t.Helper()
	w := &watcher{}
	w.cmd = exec.Command("docker", "exec", container, "mosquitto_sub", "-h", "127.0.0.1", "-t", "#", "-v")
	w.cmd.Stdout = writerFunc(func(p []byte) (int, error) { w.mu.Lock(); defer w.mu.Unlock(); return w.out.Write(p) })
	if err := w.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.cmd.Process.Kill(); _ = w.cmd.Wait() })
	time.Sleep(700 * time.Millisecond)
	return w
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func (w *watcher) expect(t *testing.T, line string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		got := w.out.String()
		w.mu.Unlock()
		if strings.Contains(got, line) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	t.Errorf("mosquitto_sub did not see %q; it saw:\n%s", line, w.out.String())
}

// TestPahoClientsThroughGateway runs the Paho MQTT-SN sample clients (an
// independent MQTT-SN 1.2 implementation) against this module's gateway,
// which relays to Mosquitto through mqttbroker, in transparent and in
// aggregating mode: QoS -1, 0 and 1 publishes on a short topic name,
// REGISTER and publishes on a registered topic, and a QoS 2 subscription
// that gets the client's own QoS 1 publish back through the broker.
// Covers: SIG-IPE-6722
func TestPahoClientsThroughGateway(t *testing.T) {
	needDocker(t)
	host := hostIPv4(t)
	for _, agg := range []bool{false, true} {
		t.Run(map[bool]string{false: "transparent", true: "aggregating"}[agg], func(t *testing.T) {
			url, container := mosquitto(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b, err := mqttbroker.Dial(ctx, mqttbroker.Options{URL: url, Aggregating: agg})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			port := freePort(t, "udp")
			pc, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = gateway.New(b, gateway.Options{}).Serve(ctx, pc); close(done) }()
			defer func() { cancel(); <-done }()
			w := watch(t, container)

			for _, s := range []struct{ sample, want string }{
				{"qos0pub", "connected rc 0"},
				{"qos-1pub", "Sending to hostname"},
				{"qos1pub", "puback received"},
			} {
				if out := runPaho(t, host, port, s.sample, 20); !strings.Contains(out, s.want) {
					t.Errorf("%s:\n%s", s.sample, out)
				}
				w.expect(t, "tt mypayload")
			}
			if out := runPaho(t, host, port, "qos0pub_register", 3); !strings.Contains(out, "regack topic id") {
				t.Errorf("qos0pub_register:\n%s", out)
			}
			w.expect(t, "iot-2/evt/status/fmt/json {")
			out := runPaho(t, host, port, "pub0sub1", 20)
			for _, want := range []string{"connected rc 0", "suback topic id", "puback received", "publish received", "puback sent"} {
				if !strings.Contains(out, want) {
					t.Errorf("pub0sub1 did not print %q:\n%s", want, out)
				}
			}
			w.expect(t, "a long topic name mypayload")
		})
	}
}
