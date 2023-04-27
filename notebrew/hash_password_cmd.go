package main

import (
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type HashPasswordCmd struct {
	Stdout   io.Writer
	Password []byte
}

func HashPasswordCommand(args ...string) (*HashPasswordCmd, error) {
	var cmd HashPasswordCmd
	if len(args) > 1 {
		return nil, fmt.Errorf("Unexpected arguments: %s", strings.Join(args[1:], " "))
	}
	if len(args) == 1 {
		cmd.Password = []byte(args[0])
		return &cmd, nil
	}
	fileinfo, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if (fileinfo.Mode() & os.ModeCharDevice) == 0 {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		cmd.Password = b
		return &cmd, nil
	}
	for {
		fmt.Fprint(os.Stderr, "Password (will be hidden from view): ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if utf8.RuneCount(password) < 8 {
			fmt.Println("Password must be at least 8 characters.")
			continue
		}
		fmt.Fprint(os.Stderr, "Confirm password (will be hidden from view): ")
		confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(password, confirmPassword) != 1 {
			fmt.Fprintln(os.Stderr, "Passwords do not match.")
			continue
		}
		cmd.Password = password
		break
	}
	return &cmd, nil
}

func (cmd *HashPasswordCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	passwordHash, err := bcrypt.GenerateFromPassword(cmd.Password, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.Stdout, string(passwordHash))
	return nil
}
