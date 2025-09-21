package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestJWT(t *testing.T) {
	type testcase struct {
		userID          uuid.UUID
		groups          []string
		wantGenerateErr error
		wantValidateErr error
	}

	testcases := []testcase{
		{uuid.New(), []string{"one", "two"}, nil, nil},
	}

	j, err := NewJWT([]byte("super-secret-key"), "test-issuer", 15*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, j)

	for _, tc := range testcases {
		token, generateErr := j.GenerateToken(tc.userID, tc.groups)
		require.ErrorIs(t, generateErr, tc.wantGenerateErr)
		if tc.wantGenerateErr == nil {
			require.NotEmpty(t, token)
		}

		claims, validateErr := j.ValidateToken(token)
		require.ErrorIs(t, validateErr, tc.wantValidateErr)
		if tc.wantValidateErr == nil {
			require.Equal(t, tc.userID, claims.Subject)
			require.Equal(t, tc.groups, claims.Groups)
		}
	}
}
