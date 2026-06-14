package config

import "testing"

func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KSEAL_POSTGRES_DSN", "postgres://localhost/kseal")
	t.Setenv("KSEAL_ENV", "dev")
}

func TestDataPlaneDefaultsToMemory(t *testing.T) {
	baseEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.DataPlane.Broker != "memory" || c.DataPlane.Analytics != "memory" {
		t.Fatalf("default backends = %q/%q, want memory/memory", c.DataPlane.Broker, c.DataPlane.Analytics)
	}
	if c.DataPlane.UsesKafka() || c.DataPlane.UsesClickHouse() {
		t.Fatal("default config must not select production backends")
	}
}

func TestKafkaSelectionRequiresBrokers(t *testing.T) {
	baseEnv(t)
	t.Setenv("KSEAL_BROKER", "kafka")
	if _, err := Load(); err == nil {
		t.Fatal("KSEAL_BROKER=kafka without KSEAL_KAFKA_BROKERS must fail closed")
	}
}

func TestClickHouseSelectionRequiresAddr(t *testing.T) {
	baseEnv(t)
	t.Setenv("KSEAL_ANALYTICS", "clickhouse")
	if _, err := Load(); err == nil {
		t.Fatal("KSEAL_ANALYTICS=clickhouse without KSEAL_CLICKHOUSE_ADDR must fail closed")
	}
}

func TestUnknownBrokerFailsClosed(t *testing.T) {
	baseEnv(t)
	t.Setenv("KSEAL_BROKER", "rabbitmq")
	if _, err := Load(); err == nil {
		t.Fatal("unknown KSEAL_BROKER must fail closed")
	}
}

func TestUnknownAnalyticsFailsClosed(t *testing.T) {
	baseEnv(t)
	t.Setenv("KSEAL_ANALYTICS", "bigquery")
	if _, err := Load(); err == nil {
		t.Fatal("unknown KSEAL_ANALYTICS must fail closed")
	}
}

func TestDataPlaneParsesFullConfig(t *testing.T) {
	baseEnv(t)
	t.Setenv("KSEAL_BROKER", "kafka")
	t.Setenv("KSEAL_KAFKA_BROKERS", "kafka-1:9092, kafka-2:9092")
	t.Setenv("KSEAL_KAFKA_TOPIC", "events")
	t.Setenv("KSEAL_KAFKA_CONSUMER_GROUP", "writer")
	t.Setenv("KSEAL_KAFKA_TLS", "true")
	t.Setenv("KSEAL_KAFKA_SASL_MECHANISM", "SCRAM-SHA-256")
	t.Setenv("KSEAL_KAFKA_SASL_USERNAME", "u")
	t.Setenv("KSEAL_KAFKA_SASL_PASSWORD", "p")
	t.Setenv("KSEAL_ANALYTICS", "clickhouse")
	t.Setenv("KSEAL_CLICKHOUSE_ADDR", "ch-1:9000,ch-2:9000")
	t.Setenv("KSEAL_CLICKHOUSE_DATABASE", "analytics")
	t.Setenv("KSEAL_CLICKHOUSE_TABLE", "events")
	t.Setenv("KSEAL_CLICKHOUSE_CLUSTER", "main")
	t.Setenv("KSEAL_CLICKHOUSE_RETENTION_TTL_DAYS", "45")
	t.Setenv("KSEAL_CLICKHOUSE_TLS", "true")

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	d := c.DataPlane
	if !d.UsesKafka() || !d.UsesClickHouse() {
		t.Fatal("both production backends should be selected")
	}
	if len(d.KafkaBrokers) != 2 || d.KafkaBrokers[0] != "kafka-1:9092" || d.KafkaBrokers[1] != "kafka-2:9092" {
		t.Fatalf("kafka brokers not parsed/trimmed: %#v", d.KafkaBrokers)
	}
	if !d.KafkaTLS || d.KafkaSASLMechanism != "scram-sha-256" {
		t.Fatalf("kafka tls/sasl not parsed: tls=%v mech=%q", d.KafkaTLS, d.KafkaSASLMechanism)
	}
	if len(d.ClickHouseAddr) != 2 || d.ClickHouseDatabase != "analytics" || d.ClickHouseCluster != "main" {
		t.Fatalf("clickhouse config not parsed: %#v", d)
	}
	if d.ClickHouseRetentionTTLDays != 45 || !d.ClickHouseTLS {
		t.Fatalf("clickhouse ttl/tls not parsed: ttl=%d tls=%v", d.ClickHouseRetentionTTLDays, d.ClickHouseTLS)
	}
}

func TestClickHouseTTLDefaultsToRawRetention(t *testing.T) {
	baseEnv(t)
	t.Setenv("KSEAL_RAW_RETENTION_DAYS", "30")
	t.Setenv("KSEAL_ANALYTICS", "clickhouse")
	t.Setenv("KSEAL_CLICKHOUSE_ADDR", "ch:9000")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.DataPlane.ClickHouseRetentionTTLDays != 30 {
		t.Fatalf("ttl should default to raw-retention window, got %d", c.DataPlane.ClickHouseRetentionTTLDays)
	}
}
