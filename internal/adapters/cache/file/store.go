package file

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/bnema/zerowrap"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/fileutil"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/cache"
	safelog "github.com/bnema/gtk4-layershell-bitwarden/internal/core/logging"
)

// Store persists encrypted cache snapshots to a JSON file on disk.
type Store struct {
	path string
}

// NewStore creates a Store that reads/writes the file at path.
func NewStore(path string) *Store {
	return &Store{path: path}
}

func cacheFileLog(ctx context.Context, operation string) (zerowrap.Logger, time.Time) {
	log := zerowrap.Logger{Logger: zerowrap.FromCtx(ctx).
		With().
		Str(zerowrap.FieldComponent, "cache.file").
		Str(zerowrap.FieldOperation, operation).
		Logger()}
	log.Info().Msg("cache file operation started")
	return log, time.Now()
}

func logCacheFileFinish(log zerowrap.Logger, started time.Time, err error, count int) {
	event := log.Info()
	msg := "cache file operation finished"
	if err != nil {
		event = log.Error().Str("error_kind", safelog.SafeErrorKind(err))
		msg = "cache file operation failed"
	}
	event.
		Int("count", count).
		Int64(zerowrap.FieldDuration, time.Since(started).Milliseconds()).
		Msg(msg)
}

// Load reads and returns the Snapshot from the JSON file.
// Returns zero Snapshot and os.ErrNotExist if the file does not exist.
func (s *Store) Load(ctx context.Context) (snap cache.Snapshot, retErr error) {
	log, started := cacheFileLog(ctx, "cache_load")
	defer func() {
		count := 0
		if retErr == nil && snap.Version != 0 {
			count = 1
		}
		logCacheFileFinish(log, started, retErr, count)
	}()

	if err := ctx.Err(); err != nil {
		return cache.Snapshot{}, err
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cache.Snapshot{}, os.ErrNotExist
		}
		return cache.Snapshot{}, err
	}

	if err := ctx.Err(); err != nil {
		return cache.Snapshot{}, err
	}

	if err := json.Unmarshal(data, &snap); err != nil {
		return cache.Snapshot{}, err
	}
	return snap, nil
}

// Save marshals the snapshot to JSON and writes it atomically to the file.
// Creates parent directories with mode 0700 if needed. Final file is mode 0600.
func (s *Store) Save(ctx context.Context, snapshot cache.Snapshot) (retErr error) {
	log, started := cacheFileLog(ctx, "cache_save")
	defer func() { logCacheFileFinish(log, started, retErr, 1) }()

	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	return fileutil.AtomicWriteFile(ctx, s.path, data, 0600)
}

// Clear removes the store file. No error if the file does not exist.
func (s *Store) Clear(ctx context.Context) (retErr error) {
	log, started := cacheFileLog(ctx, "cache_clear")
	defer func() { logCacheFileFinish(log, started, retErr, 1) }()

	if err := ctx.Err(); err != nil {
		return err
	}

	return fileutil.RemoveIfExists(s.path)
}

// Path returns the file path this store uses.
func (s *Store) Path() string {
	return s.path
}
