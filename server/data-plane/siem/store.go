package siem

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// Store errors mirror the registry's vocabulary so the Connect service can map
// them to the same gRPC/Connect codes.
var (
	ErrNotFound     = errors.New("siem: not found")
	ErrInvalidInput = errors.New("siem: invalid input")
)

// ConnectorWithSecret pairs a connector with its decrypted auth secret. Only the
// exporter ever holds the secret; it never crosses an RPC boundary.
type ConnectorWithSecret struct {
	Connector *ksealv1.SiemConnector
	Secret    []byte
}

// CreateConnectorInput carries the fields needed to register a connector. The
// secret is the plaintext auth material, sealed by the store before persistence.
type CreateConnectorInput struct {
	TenantID               string
	Kind                   ksealv1.SiemKind
	Endpoint               string
	Secret                 []byte
	Format                 ksealv1.SiemPayloadFormat
	FieldAllowList         []string
	SentinelDcrImmutableID string
	SentinelStreamName     string
	ElasticIndex           string
	SplunkIndex            string
	SplunkSourcetype       string
}

// ConnectorStore is the persistence surface for per-tenant SIEM connectors.
// Every method is tenant-scoped; the Postgres implementation additionally
// enforces row-level security. Secrets are sealed at rest with the AES-GCM
// envelope and decrypted only for the exporter via ListActiveWithSecrets.
type ConnectorStore interface {
	CreateConnector(ctx context.Context, in CreateConnectorInput) (*ksealv1.SiemConnector, error)
	ListConnectors(ctx context.Context, tenantID string) ([]*ksealv1.SiemConnector, error)
	DeleteConnector(ctx context.Context, tenantID, id string) (bool, error)
	// ListActiveWithSecrets returns active connectors and their decrypted
	// secrets for delivery. Used only by the exporter.
	ListActiveWithSecrets(ctx context.Context, tenantID string) ([]ConnectorWithSecret, error)
}

// Sealer is the subset of crypto.Encryptor the stores need. Keeping it as an
// interface lets the in-memory store run without a KEK in unit tests while the
// Postgres store uses the real envelope.
type Sealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// validateInput enforces the invariants shared by both store implementations so
// neither persists a structurally invalid connector.
func validateInput(in CreateConnectorInput) error {
	if in.TenantID == "" {
		return wrapInvalid("tenant_id required")
	}
	if in.Endpoint == "" {
		return wrapInvalid("endpoint required")
	}
	if len(in.Secret) == 0 {
		return wrapInvalid("auth secret required")
	}
	if in.Kind == ksealv1.SiemKind_SIEM_KIND_UNSPECIFIED {
		return wrapInvalid("kind required")
	}
	if !formatMatchesKind(in.Kind, in.Format) {
		return wrapInvalid("payload format incompatible with sink kind")
	}
	switch in.Kind {
	case ksealv1.SiemKind_SIEM_KIND_SENTINEL:
		if in.SentinelDcrImmutableID == "" || in.SentinelStreamName == "" {
			return wrapInvalid("sentinel connector requires dcr_immutable_id and stream_name")
		}
	case ksealv1.SiemKind_SIEM_KIND_ELASTIC:
		if in.ElasticIndex == "" {
			return wrapInvalid("elastic connector requires elastic_index")
		}
	}
	return nil
}

func wrapInvalid(msg string) error { return errInvalid{msg} }

type errInvalid struct{ msg string }

func (e errInvalid) Error() string { return "siem: " + e.msg }
func (e errInvalid) Is(target error) bool {
	return target == ErrInvalidInput
}

// formatMatchesKind enforces that a connector's payload format is the one its
// sink expects. The default (unspecified) format is resolved to the kind's
// canonical format by defaultFormatFor before this check.
func formatMatchesKind(kind ksealv1.SiemKind, format ksealv1.SiemPayloadFormat) bool {
	return format == defaultFormatFor(kind)
}

// defaultFormatFor returns the canonical payload format for a sink kind.
func defaultFormatFor(kind ksealv1.SiemKind) ksealv1.SiemPayloadFormat {
	switch kind {
	case ksealv1.SiemKind_SIEM_KIND_SPLUNK_HEC:
		return ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SPLUNK_HEC
	case ksealv1.SiemKind_SIEM_KIND_SENTINEL:
		return ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SENTINEL
	case ksealv1.SiemKind_SIEM_KIND_ELASTIC:
		return ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_ECS
	default:
		return ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_UNSPECIFIED
	}
}

// MemConnectorStore is an in-memory, concurrency-safe ConnectorStore. It backs
// unit tests and the no-database default; secrets are still sealed so the stored
// form is never plaintext.
type MemConnectorStore struct {
	enc Sealer
	mu  sync.RWMutex
	// byTenant maps tenant_id -> connector id -> stored row.
	byTenant map[string]map[string]*memRow
}

type memRow struct {
	connector *ksealv1.SiemConnector
	sealed    []byte
}

// NewMemConnectorStore builds an empty in-memory store. enc may be a no-op
// sealer in tests, but production wiring passes the real AES-GCM encryptor.
func NewMemConnectorStore(enc Sealer) *MemConnectorStore {
	return &MemConnectorStore{enc: enc, byTenant: map[string]map[string]*memRow{}}
}

// CreateConnector seals the secret and stores a new connector.
func (s *MemConnectorStore) CreateConnector(_ context.Context, in CreateConnectorInput) (*ksealv1.SiemConnector, error) {
	if in.Format == ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_UNSPECIFIED {
		in.Format = defaultFormatFor(in.Kind)
	}
	if err := validateInput(in); err != nil {
		return nil, err
	}
	allow, err := NormalizeAllowList(in.FieldAllowList)
	if err != nil {
		return nil, err
	}
	sealed, err := s.enc.Seal(in.Secret)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	c := &ksealv1.SiemConnector{
		Id:                     id,
		TenantId:               in.TenantID,
		Kind:                   in.Kind,
		Endpoint:               in.Endpoint,
		AuthSecretRef:          secretRef(id),
		Format:                 in.Format,
		FieldAllowList:         allow,
		IsActive:               true,
		CreatedAt:              nowUnix(),
		SentinelDcrImmutableId: in.SentinelDcrImmutableID,
		SentinelStreamName:     in.SentinelStreamName,
		ElasticIndex:           in.ElasticIndex,
		SplunkIndex:            in.SplunkIndex,
		SplunkSourcetype:       in.SplunkSourcetype,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[in.TenantID] == nil {
		s.byTenant[in.TenantID] = map[string]*memRow{}
	}
	s.byTenant[in.TenantID][id] = &memRow{connector: c, sealed: sealed}
	return proto.Clone(c).(*ksealv1.SiemConnector), nil
}

// ListConnectors returns the tenant's connectors (without secrets), newest first.
func (s *MemConnectorStore) ListConnectors(_ context.Context, tenantID string) ([]*ksealv1.SiemConnector, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := s.byTenant[tenantID]
	out := make([]*ksealv1.SiemConnector, 0, len(rows))
	for _, r := range rows {
		out = append(out, proto.Clone(r.connector).(*ksealv1.SiemConnector))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].Id < out[j].Id
	})
	return out, nil
}

// DeleteConnector removes a connector, reporting whether a row was deleted.
func (s *MemConnectorStore) DeleteConnector(_ context.Context, tenantID, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := s.byTenant[tenantID]
	if rows == nil {
		return false, nil
	}
	if _, ok := rows[id]; !ok {
		return false, nil
	}
	delete(rows, id)
	return true, nil
}

// ListActiveWithSecrets returns active connectors with decrypted secrets.
func (s *MemConnectorStore) ListActiveWithSecrets(_ context.Context, tenantID string) ([]ConnectorWithSecret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := s.byTenant[tenantID]
	out := make([]ConnectorWithSecret, 0, len(rows))
	for _, r := range rows {
		if !r.connector.IsActive {
			continue
		}
		secret, err := s.enc.Open(r.sealed)
		if err != nil {
			return nil, err
		}
		out = append(out, ConnectorWithSecret{
			Connector: proto.Clone(r.connector).(*ksealv1.SiemConnector),
			Secret:    secret,
		})
	}
	return out, nil
}
