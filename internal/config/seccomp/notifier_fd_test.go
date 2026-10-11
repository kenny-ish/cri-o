//go:build seccomp && linux && cgo && test

package seccomp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestHandleNewMessageSetsCloseOnExecOnReceivedFD(t *testing.T) {
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		unix.Close(sockets[0])
		unix.Close(sockets[1])
	})

	sourceFD, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(sourceFD) })

	state := []byte(`{"fds":["seccomp-fd"]}`)
	_, err = unix.SendmsgN(sockets[0], state, unix.UnixRights(sourceFD), nil, 0)
	require.NoError(t, err)

	receivedFD, err := handleNewMessage(sockets[1])
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(int(receivedFD)) })

	fdFlags, err := unix.FcntlInt(uintptr(receivedFD), unix.F_GETFD, 0)
	require.NoError(t, err)
	require.NotZero(t, fdFlags&unix.FD_CLOEXEC)
}
