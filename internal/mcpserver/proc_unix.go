//go:build !windows

package mcpserver

import (
	osexec "os/exec"
	"syscall"
)

// killProcessTreeOnCancel starts cmd in its own process group and makes
// context cancellation SIGKILL the whole group.
func killProcessTreeOnCancel(cmd *osexec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// A negative pid signals every process in the group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
