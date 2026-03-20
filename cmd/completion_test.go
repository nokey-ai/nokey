package cmd

import (
	"strings"
	"testing"
)

func TestCompletionBash(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"completion", "bash"})
		rootCmd.Execute()
	})
	if !strings.Contains(out, "bash completion") {
		t.Error("bash completion output should contain 'bash completion'")
	}
}

func TestCompletionZsh(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"completion", "zsh"})
		rootCmd.Execute()
	})
	if !strings.Contains(out, "zsh") {
		t.Error("zsh completion output should reference zsh")
	}
}

func TestCompletionFish(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"completion", "fish"})
		rootCmd.Execute()
	})
	if !strings.Contains(out, "fish") {
		t.Error("fish completion output should reference fish")
	}
}

func TestCompletionPowershell(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"completion", "powershell"})
		rootCmd.Execute()
	})
	if !strings.Contains(out, "nokey") {
		t.Error("powershell completion output should reference nokey")
	}
}

func TestCompletionInvalidShell(t *testing.T) {
	rootCmd.SetArgs([]string{"completion", "invalid"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("completion with invalid shell should fail")
	}
}

func TestCompletionNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"completion"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("completion with no args should fail")
	}
}
