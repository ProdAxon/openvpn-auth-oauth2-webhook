package tokenstorage

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// FileStorage wraps InMemory storage and persists to a JSON file.
// It provides the same functionality as InMemory but survives service restarts.
type FileStorage struct {
	*InMemory

	filePath string
	saveMu   sync.Mutex // separate mutex for file operations
	logger   *slog.Logger
}

// NewFileStorage creates a new file-backed token storage.
// It loads existing tokens from the file on startup if it exists.
func NewFileStorage(logger *slog.Logger, encryptionKey string, expires time.Duration, filePath string) *FileStorage {
	fs := &FileStorage{
		InMemory: NewInMemory(encryptionKey, expires),
		filePath: filePath,
		logger:   logger,
	}

	// Load existing tokens on startup
	if err := fs.loadFromFile(); err != nil {
		logger.Warn("failed to load tokens from file, starting fresh",
			slog.String("path", filePath),
			slog.Any("error", err),
		)
	}

	return fs
}

// Set stores an encrypted token for a given client and persists to file.
func (fs *FileStorage) Set(client, token string) error {
	if err := fs.InMemory.Set(client, token); err != nil {
		return err
	}

	if err := fs.saveToFile(); err != nil {
		fs.logger.Error("failed to persist token to file",
			slog.String("client", client),
			slog.Any("error", err),
		)
		// Don't return error - token is still in memory
	}

	return nil
}

// Delete removes the token for a client and persists to file.
func (fs *FileStorage) Delete(client string) error {
	if err := fs.InMemory.Delete(client); err != nil {
		return err
	}

	if err := fs.saveToFile(); err != nil {
		fs.logger.Error("failed to persist token deletion to file",
			slog.String("client", client),
			slog.Any("error", err),
		)
		// Don't return error - token is still deleted from memory
	}

	return nil
}

// Close saves the current state to file before closing.
func (fs *FileStorage) Close() error {
	return fs.saveToFile()
}

// loadFromFile reads tokens from the JSON file and loads them into memory.
// Expired tokens are filtered out during loading.
func (fs *FileStorage) loadFromFile() error {
	fs.saveMu.Lock()
	defer fs.saveMu.Unlock()

	data, err := os.ReadFile(fs.filePath)
	if os.IsNotExist(err) {
		fs.logger.Info("no existing token file, starting fresh",
			slog.String("path", fs.filePath),
		)

		return nil // No file yet, start fresh
	}

	if err != nil {
		return fmt.Errorf("read file error: %w", err)
	}

	var dataMap DataMap
	if err := json.Unmarshal(data, &dataMap); err != nil {
		return fmt.Errorf("unmarshal error: %w", err)
	}

	// Filter out expired tokens while loading
	now := time.Now()
	filtered := DataMap{}
	expiredCount := 0

	for k, v := range dataMap {
		if v.Expires.After(now) {
			filtered[k] = v
		} else {
			expiredCount++
		}
	}

	if err := fs.SetStorage(filtered); err != nil {
		return fmt.Errorf("set storage error: %w", err)
	}

	fs.logger.Info("loaded tokens from file",
		slog.String("path", fs.filePath),
		slog.Int("loaded", len(filtered)),
		slog.Int("expired_filtered", expiredCount),
	)

	return nil
}

// saveToFile persists the current token state to the JSON file.
// Uses atomic write (write to temp file, then rename) to prevent corruption.
func (fs *FileStorage) saveToFile() error {
	fs.saveMu.Lock()
	defer fs.saveMu.Unlock()

	fs.mu.RLock()
	data, err := json.Marshal(fs.data)
	fs.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tmpFile := fs.filePath + ".tmp"

	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("write temp file error: %w", err)
	}

	if err := os.Rename(tmpFile, fs.filePath); err != nil {
		// Try to clean up temp file
		_ = os.Remove(tmpFile)

		return fmt.Errorf("rename error: %w", err)
	}

	return nil
}
