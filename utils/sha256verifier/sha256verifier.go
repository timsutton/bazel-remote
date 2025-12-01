package sha256verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"github.com/zeebo/blake3"
)

type sha256verifier struct {
	hash.Hash
	expectedSize        int64
	expectedHash        string
	actualSize          int64
	multiWriter         io.Writer
	originalWriteCloser io.WriteCloser
}

// HashAlgorithm represents the type of hash algorithm to use
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "sha256"
	BLAKE3 HashAlgorithm = "blake3"
)

// New creates a new hash verifier using SHA256
func New(expectedHash string, expectedSize int64, writeCloser io.WriteCloser) *sha256verifier {
	return NewWithAlgorithm(SHA256, expectedHash, expectedSize, writeCloser)
}

// NewWithAlgorithm creates a new hash verifier using the specified algorithm
func NewWithAlgorithm(algorithm HashAlgorithm, expectedHash string, expectedSize int64, writeCloser io.WriteCloser) *sha256verifier {
	var h hash.Hash

	switch algorithm {
	case BLAKE3:
		h = blake3.New()
	case SHA256:
		fallthrough
	default:
		h = sha256.New()
	}

	return &sha256verifier{
		Hash:                h,
		expectedHash:        expectedHash,
		expectedSize:        expectedSize,
		multiWriter:         io.MultiWriter(h, writeCloser),
		originalWriteCloser: writeCloser,
	}
}

func (s *sha256verifier) Write(p []byte) (int, error) {

	n, err := s.multiWriter.Write(p)
	if n > 0 {
		s.actualSize += int64(n)
	}

	return n, err
}

func (s *sha256verifier) Close() error {
	if s.actualSize != s.expectedSize {
		return fmt.Errorf("error: expected %d bytes, got %d", s.expectedSize, s.actualSize)
	}

	actualHash := hex.EncodeToString(s.Sum(nil))
	if actualHash != s.expectedHash {
		return fmt.Errorf("error: expected hash %s, got %s", s.expectedHash, actualHash)
	}

	err := s.originalWriteCloser.Close()
	if err != nil {
		return err
	}

	return nil
}
