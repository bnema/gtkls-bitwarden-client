package cache

import "time"

const Version = 1

type Snapshot struct {
	Version          int
	AccountHash      string
	LastRevision     string
	SavedAt          time.Time
	CacheKeySalt     []byte
	VaultCiphertext  []byte
	OutboxCiphertext []byte
}

type PlainSnapshot struct {
	AccountHash   string
	LastRevision  string
	SavedAt       time.Time
	CacheKeySalt  []byte
	ItemsJSON     []byte
	FoldersJSON   []byte
	OutboxJSON    []byte
	ConflictsJSON []byte
}
