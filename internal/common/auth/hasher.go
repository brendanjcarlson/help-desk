package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidHash        = errors.New("invalid hash")
)

type Argon2 struct {
	memory     uint32
	iterations uint32
	threads    uint8
	saltLength uint32
	keyLength  uint32
}

func defaultArgon2() *Argon2 {
	return &Argon2{
		memory:     64 * 1024,
		iterations: 2,
		threads:    uint8(runtime.NumCPU()),
		saltLength: 16,
		keyLength:  32,
	}
}

func NewArgon2(options ...Argon2Option) (*Argon2, error) {
	a := defaultArgon2()
	for _, option := range options {
		if err := option(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *Argon2) GenerateFromPassword(password []byte) (string, error) {
	salt := make([]byte, a.saltLength)
	n, err := rand.Read(salt)
	if n != int(a.saltLength) || err != nil {
		return "", fmt.Errorf("failed to generate salt")
	}
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)

	key := argon2.IDKey(password, salt, a.iterations, a.memory, a.threads, a.keyLength)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.memory, a.iterations, a.threads,
		b64Salt,
		b64Key,
	), nil
}

func (a *Argon2) ComparePasswordAndHash(password []byte, hash string) error {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return errors.Join(ErrInvalidHash, err)
	}

	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return errors.Join(ErrInvalidHash, err)
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return errors.Join(ErrInvalidHash, err)
	}

	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return errors.Join(ErrInvalidHash, err)
	}
	keyLength := uint32(len(key))

	comparisonKey := argon2.IDKey(password, salt, iterations, memory, threads, keyLength)

	if subtle.ConstantTimeCompare(key, comparisonKey) == 0 {
		return ErrInvalidCredentials
	}

	return nil
}

type Argon2Option func(*Argon2) error

// TODO: validate min memory
func WithArgon2Memory(memory uint32) Argon2Option {
	return func(a *Argon2) error {
		a.memory = memory
		return nil
	}
}

// TODO: validate min iterations
func WithArgon2Iterations(iterations uint32) Argon2Option {
	return func(a *Argon2) error {
		a.iterations = iterations
		return nil
	}
}

// TODO: validate threads
func WithArgon2Threads(threads uint8) Argon2Option {
	return func(a *Argon2) error {
		a.threads = threads
		return nil
	}
}

// TODO: validate salt length
func WithArgon2SaltLength(saltLength uint32) Argon2Option {
	return func(a *Argon2) error {
		a.saltLength = saltLength
		return nil
	}
}

// TODO: validate key length
func WithArgon2KeyLength(keyLength uint32) Argon2Option {
	return func(a *Argon2) error {
		a.keyLength = keyLength
		return nil
	}
}
