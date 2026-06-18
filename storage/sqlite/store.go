// SPDX-License-Identifier: Apache-2.0

package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/BitBoxSwiss/bitboxsync-client-go/bitboxsync"
	_ "github.com/mattn/go-sqlite3"
)

// Store is the default SQLite-backed implementation of the bitboxsync.Store
// interface.
type Store struct {
	db *sql.DB
}

var inMemoryStoreCounter atomic.Uint64

// Open opens or creates a SQLite-backed sync store at path.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// OpenInMemory opens an in-memory SQLite-backed sync store.
func OpenInMemory() (*Store, error) {
	id := inMemoryStoreCounter.Add(1)
	return Open(fmt.Sprintf("file:bitboxsync-%d?mode=memory&cache=shared", id))
}

// Close releases the underlying SQLite database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// LoadIdentity loads persisted auth/session state for one device identity.
func (s *Store) LoadIdentity(ctx context.Context, keyID string) (bitboxsync.IdentityState, error) {
	var state bitboxsync.IdentityState
	var tokenExpiry sql.NullTime
	var defaultNamespaceID sql.NullString
	err := s.db.QueryRowContext(
		ctx,
		`SELECT key_id, kind, access_token, token_expiry, default_namespace_id, updated_at
		   FROM identity_states
		  WHERE key_id = ?`,
		keyID,
	).Scan(&state.KeyID, &state.Kind, &state.AccessToken, &tokenExpiry, &defaultNamespaceID, &state.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return bitboxsync.IdentityState{}, bitboxsync.ErrNotFound
	}
	if err != nil {
		return bitboxsync.IdentityState{}, err
	}
	if tokenExpiry.Valid {
		state.TokenExpiry = tokenExpiry.Time
	}
	if defaultNamespaceID.Valid {
		state.DefaultNamespaceID = defaultNamespaceID.String
	}
	return state, nil
}

// SaveIdentity upserts persisted auth/session state for one device identity.
func (s *Store) SaveIdentity(ctx context.Context, state bitboxsync.IdentityState) error {
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO identity_states (key_id, kind, access_token, token_expiry, default_namespace_id, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key_id) DO UPDATE SET
		     kind = excluded.kind,
		     access_token = excluded.access_token,
		     token_expiry = excluded.token_expiry,
		     default_namespace_id = excluded.default_namespace_id,
		     updated_at = excluded.updated_at`,
		state.KeyID,
		state.Kind,
		state.AccessToken,
		nullTime(state.TokenExpiry),
		nullString(state.DefaultNamespaceID),
		state.UpdatedAt,
	)
	return err
}

// GetNamespace loads cached namespace metadata for one device identity.
func (s *Store) GetNamespace(ctx context.Context, keyID, namespaceID string) (bitboxsync.NamespaceState, error) {
	var state bitboxsync.NamespaceState
	err := s.db.QueryRowContext(
		ctx,
		`SELECT key_id, namespace_id, kind, namespace_head, active_scope_hash, dek, updated_at
		   FROM namespaces
		  WHERE key_id = ? AND namespace_id = ?`,
		keyID, namespaceID,
	).Scan(&state.KeyID, &state.NamespaceID, &state.Kind, &state.NamespaceHead, &state.ActiveScopeHash, &state.DEK, &state.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return bitboxsync.NamespaceState{}, bitboxsync.ErrNotFound
	}
	if err != nil {
		return bitboxsync.NamespaceState{}, err
	}
	state.DEK = bytes.Clone(state.DEK)
	return state, nil
}

// ListNamespaces returns all namespaces cached for one device identity.
func (s *Store) ListNamespaces(ctx context.Context, keyID string) (states []bitboxsync.NamespaceState, err error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT key_id, namespace_id, kind, namespace_head, active_scope_hash, dek, updated_at
		   FROM namespaces
		  WHERE key_id = ?
		  ORDER BY updated_at, namespace_id`,
		keyID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	for rows.Next() {
		var state bitboxsync.NamespaceState
		if err := rows.Scan(&state.KeyID, &state.NamespaceID, &state.Kind, &state.NamespaceHead, &state.ActiveScopeHash, &state.DEK, &state.UpdatedAt); err != nil {
			return nil, err
		}
		state.DEK = bytes.Clone(state.DEK)
		states = append(states, state)
	}
	return states, rows.Err()
}

// SaveNamespace upserts cached namespace metadata and secrets.
func (s *Store) SaveNamespace(ctx context.Context, state bitboxsync.NamespaceState) error {
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO namespaces (key_id, namespace_id, kind, namespace_head, active_scope_hash, dek, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key_id, namespace_id) DO UPDATE SET
		     kind = excluded.kind,
		     namespace_head = excluded.namespace_head,
		     active_scope_hash = excluded.active_scope_hash,
		     dek = excluded.dek,
		     updated_at = excluded.updated_at`,
		state.KeyID,
		state.NamespaceID,
		state.Kind,
		state.NamespaceHead,
		state.ActiveScopeHash,
		state.DEK,
		state.UpdatedAt,
	)
	return err
}

// ForgetIdentitySecrets clears locally cached secrets for one identity while
// preserving namespace and item metadata for future merge reconciliation.
func (s *Store) ForgetIdentitySecrets(ctx context.Context, keyID string) error {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE identity_states
		    SET access_token = '',
		        token_expiry = NULL,
		        updated_at = ?
		  WHERE key_id = ?`,
		now,
		keyID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE namespaces
		    SET dek = NULL,
		        updated_at = ?
		  WHERE key_id = ?`,
		now,
		keyID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// GetItemByID loads one cached item by its opaque item ID.
func (s *Store) GetItemByID(ctx context.Context, keyID, namespaceID, itemID string) (bitboxsync.ItemState, error) {
	return s.getItem(ctx, `SELECT key_id, namespace_id, collection_name, item_key, item_id, version, base_version, base_value, dirty, conflict, conflict_remote_version, conflict_remote_value, updated_at
		                 FROM items
		                WHERE key_id = ? AND namespace_id = ? AND item_id = ?`, keyID, namespaceID, itemID)
}

// GetItemByLogicalKey loads one cached item by collection name and logical key.
func (s *Store) GetItemByLogicalKey(ctx context.Context, keyID, namespaceID, collection, key string) (bitboxsync.ItemState, error) {
	return s.getItem(ctx, `SELECT key_id, namespace_id, collection_name, item_key, item_id, version, base_version, base_value, dirty, conflict, conflict_remote_version, conflict_remote_value, updated_at
		                 FROM items
		                WHERE key_id = ? AND namespace_id = ? AND collection_name = ? AND item_key = ?`, keyID, namespaceID, collection, key)
}

// ListNamespaceItems returns all cached items for a namespace.
func (s *Store) ListNamespaceItems(ctx context.Context, keyID, namespaceID string) (items []bitboxsync.ItemState, err error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT key_id, namespace_id, collection_name, item_key, item_id, version, base_version, base_value, dirty, conflict, conflict_remote_version, conflict_remote_value, updated_at
		   FROM items
		  WHERE key_id = ? AND namespace_id = ?
		  ORDER BY updated_at, item_id`,
		keyID, namespaceID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListDirtyItems returns cached items with unapplied local changes.
func (s *Store) ListDirtyItems(ctx context.Context, keyID string) (items []bitboxsync.ItemState, err error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT key_id, namespace_id, collection_name, item_key, item_id, version, base_version, base_value, dirty, conflict, conflict_remote_version, conflict_remote_value, updated_at
		   FROM items
		  WHERE key_id = ? AND dirty = 1
		  ORDER BY updated_at, item_id`,
		keyID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// SaveItem upserts the cached state for one item, including conflict metadata.
func (s *Store) SaveItem(ctx context.Context, state bitboxsync.ItemState) error {
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO items (
		     key_id, namespace_id, collection_name, item_key, item_id, version, base_version, base_value, dirty, conflict, conflict_remote_version, conflict_remote_value, updated_at
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key_id, namespace_id, item_id) DO UPDATE SET
		     collection_name = excluded.collection_name,
		     item_key = excluded.item_key,
		     version = excluded.version,
		     base_version = excluded.base_version,
		     base_value = excluded.base_value,
		     dirty = excluded.dirty,
		     conflict = excluded.conflict,
		     conflict_remote_version = excluded.conflict_remote_version,
		     conflict_remote_value = excluded.conflict_remote_value,
		     updated_at = excluded.updated_at`,
		state.KeyID,
		state.NamespaceID,
		state.Collection,
		state.Key,
		state.ItemID,
		state.Version,
		state.BaseVersion,
		nullBytes(state.BaseValue),
		boolToInt(state.Dirty),
		boolToInt(state.Conflict),
		state.ConflictRemoteVersion,
		nullBytes(state.ConflictRemoteValue),
		state.UpdatedAt,
	)
	return err
}

// init applies the SQLite schema and runtime pragmas required by the store.
func (s *Store) init() error {
	stmts := []string{
		`PRAGMA journal_mode = WAL;`,
		`PRAGMA foreign_keys = ON;`,
		`PRAGMA busy_timeout = 5000;`,
		`CREATE TABLE IF NOT EXISTS identity_states (
		    key_id TEXT PRIMARY KEY,
		    kind TEXT NOT NULL,
		    access_token TEXT NOT NULL DEFAULT '',
		    token_expiry TIMESTAMP NULL,
		    default_namespace_id TEXT NULL,
		    updated_at TIMESTAMP NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS namespaces (
		    key_id TEXT NOT NULL,
		    namespace_id TEXT NOT NULL,
		    kind TEXT NOT NULL,
		    namespace_head INTEGER NOT NULL DEFAULT 0,
		    active_scope_hash TEXT NOT NULL DEFAULT '',
		    dek BLOB NULL,
		    updated_at TIMESTAMP NOT NULL,
		    PRIMARY KEY (key_id, namespace_id)
		);`,
		`CREATE TABLE IF NOT EXISTS items (
		    key_id TEXT NOT NULL,
		    namespace_id TEXT NOT NULL,
		    collection_name TEXT NOT NULL,
		    item_key TEXT NOT NULL,
		    item_id TEXT NOT NULL,
		    version INTEGER NOT NULL DEFAULT 0,
		    base_version INTEGER NOT NULL DEFAULT 0,
		    base_value BLOB NULL,
		    dirty INTEGER NOT NULL DEFAULT 0,
		    conflict INTEGER NOT NULL DEFAULT 0,
		    conflict_remote_version INTEGER NOT NULL DEFAULT 0,
		    conflict_remote_value BLOB NULL,
		    updated_at TIMESTAMP NOT NULL,
		    PRIMARY KEY (key_id, namespace_id, item_id)
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_items_logical_key
		   ON items (key_id, namespace_id, collection_name, item_key);`,
		`CREATE INDEX IF NOT EXISTS idx_items_dirty
		   ON items (key_id, dirty, updated_at);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// getItem loads one item using the supplied query and normalizes not-found
// handling.
func (s *Store) getItem(ctx context.Context, query string, args ...any) (bitboxsync.ItemState, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	item, err := scanItem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return bitboxsync.ItemState{}, bitboxsync.ErrNotFound
	}
	if err != nil {
		return bitboxsync.ItemState{}, err
	}
	return item, nil
}

// itemScanner describes the subset of Scan behavior needed by scanItem.
type itemScanner interface {
	// Scan copies the current row into the provided destinations following the
	// database/sql Scanner contract.
	Scan(dest ...any) error
}

// scanItem converts a scanned row into an ItemState with copied byte slices and
// boolean flags.
func scanItem(scanner itemScanner) (bitboxsync.ItemState, error) {
	var item bitboxsync.ItemState
	var dirty, conflict int
	err := scanner.Scan(
		&item.KeyID,
		&item.NamespaceID,
		&item.Collection,
		&item.Key,
		&item.ItemID,
		&item.Version,
		&item.BaseVersion,
		&item.BaseValue,
		&dirty,
		&conflict,
		&item.ConflictRemoteVersion,
		&item.ConflictRemoteValue,
		&item.UpdatedAt,
	)
	if err != nil {
		return bitboxsync.ItemState{}, err
	}
	item.BaseValue = bytes.Clone(item.BaseValue)
	item.ConflictRemoteValue = bytes.Clone(item.ConflictRemoteValue)
	item.Dirty = dirty != 0
	item.Conflict = conflict != 0
	return item, nil
}

// nullString converts an empty string into SQL NULL.
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// nullTime converts a zero time into SQL NULL.
func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

// nullBytes converts a nil byte slice into SQL NULL.
func nullBytes(value []byte) any {
	if value == nil {
		return nil
	}
	return value
}

// boolToInt converts a boolean into the integer representation used in SQLite.
func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// cloneBytes returns a copy of value.
