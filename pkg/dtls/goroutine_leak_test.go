package dtls

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func passGoroutineLeak(testFunc func(*testing.T), t *testing.T) bool {
	initialGoroutines := runtime.NumGoroutine()

	testFunc(t)

	time.Sleep(2 * time.Second)

	return runtime.NumGoroutine() <= initialGoroutines
}

func TestGoroutineLeak(t *testing.T) {
	testFuncs := []func(*testing.T){TestSend, TestServerFail, TestClientFail, TestListenSuccess, TestListenFail, TestFailSCTP}

	for _, test := range testFuncs {
		require.True(t, passGoroutineLeak(test, t))
	}

}
