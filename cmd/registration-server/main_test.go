package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseClientConf(t *testing.T) {
	clientConfPath := "./testdata/ClientConf"

	cc, err := parseClientConf(clientConfPath)
	require.Nil(t, err)

	require.NotNil(t, cc)
	require.Equal(t, uint32(1153), cc.GetGeneration())
}
