// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"bytes"
	"encoding/json"
	"errors"
)

// codecFunc adapts encode and decode functions into the Codec interface.
type codecFunc[T any] struct {
	encode func(T) ([]byte, error)
	decode func([]byte) (T, error)
}

// Encode serializes a value using the codec function pair.
func (c codecFunc[T]) Encode(value T) ([]byte, error) {
	return c.encode(value)
}

// Decode deserializes a value using the codec function pair.
func (c codecFunc[T]) Decode(value []byte) (T, error) {
	return c.decode(value)
}

// JSONCodec returns a codec that serializes values as JSON.
func JSONCodec[T any]() Codec[T] {
	return codecFunc[T]{
		encode: func(value T) ([]byte, error) {
			return json.Marshal(value)
		},
		decode: func(payload []byte) (T, error) {
			var out T
			if len(payload) == 0 {
				return out, errors.New("empty JSON payload")
			}
			if err := json.Unmarshal(payload, &out); err != nil {
				return out, err
			}
			return out, nil
		},
	}
}

// StringCodec returns a codec that stores strings as UTF-8 bytes.
func StringCodec() Codec[string] {
	return codecFunc[string]{
		encode: func(value string) ([]byte, error) {
			return []byte(value), nil
		},
		decode: func(payload []byte) (string, error) {
			return string(payload), nil
		},
	}
}

// BytesCodec returns a codec that stores raw byte slices without additional
// encoding.
func BytesCodec() Codec[[]byte] {
	return codecFunc[[]byte]{
		encode: func(value []byte) ([]byte, error) {
			out := make([]byte, len(value))
			copy(out, value)
			return out, nil
		},
		decode: func(payload []byte) ([]byte, error) {
			out := make([]byte, len(payload))
			copy(out, payload)
			return out, nil
		},
	}
}

// EqualBytes reports whether two byte slices contain the same bytes.
func EqualBytes(left, right []byte) bool {
	return bytes.Equal(left, right)
}
