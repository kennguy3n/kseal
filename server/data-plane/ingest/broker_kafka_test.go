package ingest

import (
	"strings"
	"testing"
	"time"
)

func TestKafkaConfigDefaults(t *testing.T) {
	c := KafkaConfig{Brokers: []string{"b:9092"}}
	c.withDefaults()
	if c.Topic != "kseal.telemetry.events" {
		t.Fatalf("default topic = %q", c.Topic)
	}
	if c.ConsumerGroup != "kseal-analytics-writer" {
		t.Fatalf("default group = %q", c.ConsumerGroup)
	}
	if c.ProducerBufferRecords <= 0 || c.ConsumeChannelBuffer <= 0 || c.ProducerRetries <= 0 {
		t.Fatalf("buffers/retries must default positive: %+v", c)
	}
	if c.CommitInterval <= 0 || c.DialTimeout <= 0 {
		t.Fatalf("intervals must default positive: %+v", c)
	}
}

func TestKafkaConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     KafkaConfig
		wantErr bool
	}{
		{"no brokers", KafkaConfig{}, true},
		{"ok plain", KafkaConfig{Brokers: []string{"b:9092"}, SASLMechanism: "plain", SASLUsername: "u", SASLPassword: "p"}, false},
		{"unknown mech", KafkaConfig{Brokers: []string{"b:9092"}, SASLMechanism: "kerberos"}, true},
		{"sasl missing creds", KafkaConfig{Brokers: []string{"b:9092"}, SASLMechanism: "scram-sha-256"}, true},
		{"no sasl ok", KafkaConfig{Brokers: []string{"b:9092"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.withDefaults()
			err := tc.cfg.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestKafkaClientOptionsBuildsForEachSASL(t *testing.T) {
	for _, mech := range []string{"", "plain", "scram-sha-256", "scram-sha-512"} {
		c := KafkaConfig{Brokers: []string{"b:9092"}, SASLMechanism: mech, SASLUsername: "u", SASLPassword: "p"}
		c.withDefaults()
		opts, err := c.clientOptions()
		if err != nil {
			t.Fatalf("mech %q: %v", mech, err)
		}
		if len(opts) == 0 {
			t.Fatalf("mech %q: no client options built", mech)
		}
	}
}

func TestKafkaTLSConfigRejectsBadCA(t *testing.T) {
	c := KafkaConfig{Brokers: []string{"b:9092"}, TLS: true, CAFile: writeTempFile(t, "not a pem")}
	if _, err := c.tlsConfig(); err == nil {
		t.Fatal("expected error for CA file with no valid certs")
	}
}

func TestKafkaTLSConfigMissingCAFile(t *testing.T) {
	c := KafkaConfig{Brokers: []string{"b:9092"}, TLS: true, CAFile: "/no/such/ca.pem"}
	if _, err := c.tlsConfig(); err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

// NewKafkaBroker must fail closed (not hang or panic) when the cluster is
// unreachable, so an explicit Kafka selection never silently degrades.
func TestNewKafkaBrokerFailsClosedOnUnreachable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping unreachable-broker dial in -short mode")
	}
	done := make(chan error, 1)
	go func() {
		// 127.0.0.1:1 refuses immediately; tight dial timeout bounds the test.
		b, err := NewKafkaBroker(t.Context(), KafkaConfig{
			Brokers:     []string{"127.0.0.1:1"},
			DialTimeout: 2 * time.Second,
		})
		if b != nil {
			b.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for unreachable broker")
		}
		if !strings.Contains(err.Error(), "kafka") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("NewKafkaBroker did not fail closed within timeout")
	}
}
