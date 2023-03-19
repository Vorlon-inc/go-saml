package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompressString(t *testing.T) {
	expected := "This is the test string"
	compressed, err := compressString(expected)
	assert.NoError(t, err)
	decompressed, err := decompressString(compressed)
	assert.NoError(t, err)
	assert.Equal(t, expected, decompressed)
	assert.True(t, len(compressed) > len(decompressed))
}

func TestCompress(t *testing.T) {
	expected := []byte("This is the test string")
	compressed, err := compress(expected)
	assert.NoError(t, err)
	decompressed, err := decompress(compressed)
	assert.NoError(t, err)
	assert.Equal(t, expected, decompressed)
	assert.True(t, len(compressed) > len(decompressed))
}
