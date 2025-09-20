package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArgon2(t *testing.T) {
	type testcase struct {
		password   string
		comparison string
		wantErr    error
	}

	testcases := []testcase{
		{"password", "password", nil},
		{"password", "WrOnG", ErrInvalidCredentials},
	}

	// tune it down for testing
	a, err := NewArgon2(
		WithArgon2Memory(8*1024),
		WithArgon2Iterations(2),
		WithArgon2Threads(1),
	)
	require.NoError(t, err)
	require.NotNil(t, a)

	for _, tc := range testcases {
		hash1, err := a.GenerateFromPassword([]byte(tc.password))
		require.NoError(t, err)
		require.NotEmpty(t, hash1)

		hash2, err := a.GenerateFromPassword([]byte(tc.password))
		require.NoError(t, err)
		require.NotEmpty(t, hash2)

		require.NotEqual(t, hash1, hash2)

		err1 := a.ComparePasswordAndHash([]byte(tc.comparison), hash1)
		require.ErrorIs(t, err1, tc.wantErr)

		err2 := a.ComparePasswordAndHash([]byte(tc.comparison), hash2)
		require.ErrorIs(t, err2, tc.wantErr)
	}
}
