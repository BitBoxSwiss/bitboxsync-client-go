// SPDX-License-Identifier: Apache-2.0

package bitboxsync

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJSONCodecRejectsEmptyPayload(t *testing.T) {
	codec := JSONCodec[map[string]string]()
	_, err := codec.Decode(nil)
	require.Error(t, err)
	_, err = codec.Decode([]byte{})
	require.Error(t, err)
}
