//go:build windows

package mcpserver

import osexec "os/exec"

// killProcessTreeOnCancel leaves the default cancellation (killing the
// direct child) in place; cmd.WaitDelay bounds any wait on descendants.
func killProcessTreeOnCancel(cmd *osexec.Cmd) {}
