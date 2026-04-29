package cache

import "time"

const Version = 1

type Snapshot struct {
	Version          int
	AccountHash      string
	LastRevision     string
	SavedAt          time.Time
	VaultCiphertext  []byte
	OutboxCiphertext []byte
}

type PlainSnapshot struct {
	AccountHash  string
	LastRevision string
	ItemsJSON    []byte
	FoldersJSON  []byte
	OutboxJSON   []byte
}
