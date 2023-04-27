package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/nb3"
	"github.com/bokwoon95/sq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type ResetPasswordCmd struct {
	Notebrew     *nb3.Notebrew
	Stdout       io.Writer
	Stderr       io.Writer
	Email        string
	PasswordHash string
	ResetLink    bool
}

func ResetPasswordCommand(nb *nb3.Notebrew, args ...string) (*ResetPasswordCmd, error) {
	var cmd ResetPasswordCmd
	cmd.Notebrew = nb
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.StringVar(&cmd.Email, "email", "", "")
	flagset.StringVar(&cmd.PasswordHash, "password-hash", "", "")
	flagset.BoolVar(&cmd.ResetLink, "reset-link", false, "")
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	flagArgs := flagset.Args()
	if len(flagArgs) > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagArgs, " "))
	}
	reader := bufio.NewReader(os.Stdin)

	cmd.Email = strings.TrimSpace(cmd.Email)
	if cmd.Email == "" {
		for {
			fmt.Print("Email: ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.Email = strings.TrimSpace(text)
			if cmd.Email == "" {
				fmt.Println("Email cannot be empty.")
				continue
			}
			break
		}
	}

	USERS := sq.New[nb3.USERS]("")
	exists, err := sq.FetchExists(cmd.Notebrew.DB, sq.SelectQuery{
		Dialect: cmd.Notebrew.Dialect,
		SelectFields: []sq.Field{
			sq.Expr("1"),
		},
		FromTable:      USERS,
		WherePredicate: USERS.EMAIL.EqString(cmd.Email),
	})
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no such user with email %s", cmd.Email)
	}

	if cmd.ResetLink {
		return &cmd, nil
	}

	if cmd.PasswordHash == "" {
		for {
			fmt.Print("Password (will be hidden from view, leave blank to generate password reset link): ")
			password, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return nil, err
			}
			if len(password) == 0 {
				cmd.ResetLink = true
				return &cmd, nil
			}
			if utf8.RuneCount(password) < 8 {
				fmt.Println("Password must be at least 8 characters.")
				continue
			}
			fmt.Print("Confirm password (will be hidden from view): ")
			confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return nil, err
			}
			if subtle.ConstantTimeCompare(password, confirmPassword) != 1 {
				fmt.Fprintln(os.Stderr, "Passwords do not match.")
				continue
			}
			b, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			cmd.PasswordHash = string(b)
			break
		}
	}
	return &cmd, nil
}

func (cmd *ResetPasswordCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	var (
		USERS    = sq.New[nb3.USERS]("")
		LOGINS   = sq.New[nb3.LOGINS]("")
		SITES    = sq.New[nb3.SITES]("")
		SESSIONS = sq.New[nb3.SESSIONS]("")
	)
	if cmd.ResetLink {
		var resetToken [8 + 16]byte
		binary.BigEndian.PutUint64(resetToken[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(resetToken[8:])
		if err != nil {
			return err
		}
		checksum := sha256.Sum256([]byte(resetToken[8:]))
		var resetTokenHash [8 + sha256.Size]byte
		copy(resetTokenHash[:8], resetToken[:8])
		copy(resetTokenHash[8:], checksum[:])
		_, err = sq.Exec(cmd.Notebrew.DB, sq.UpdateQuery{
			Dialect:     cmd.Notebrew.Dialect,
			UpdateTable: USERS,
			Assignments: []sq.Assignment{
				USERS.RESET_TOKEN_HASH.SetBytes(resetTokenHash[:]),
			},
			WherePredicate: USERS.EMAIL.EqString(cmd.Email),
		})
		if err != nil {
			return err
		}
		var link string
		values := make(url.Values)
		values.Set("token", strings.TrimLeft(hex.EncodeToString(resetToken[:]), "0"))
		query := values.Encode()
		if cmd.Notebrew.AdminDomain == "" {
			link = "http://localhost:" + strconv.Itoa(cmd.Notebrew.Port) + "/admin/resetpassword/?" + query
		} else if cmd.Notebrew.MultisiteMode == "subdomain" {
			link = "https://www." + cmd.Notebrew.AdminDomain + "/admin/resetpassword/?" + query
		} else {
			link = "https://" + cmd.Notebrew.AdminDomain + "/admin/resetpassword/?" + query
		}
		fmt.Fprintf(cmd.Stderr, "Password reset link generated for %s:\n", cmd.Email)
		_, err = fmt.Fprintln(cmd.Stdout, link)
		return err
	}
	tx, err := cmd.Notebrew.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = sq.Exec(tx, sq.DeleteQuery{
		Dialect:     cmd.Notebrew.Dialect,
		DeleteTable: LOGINS,
		WherePredicate: sq.Exists(sq.SelectQuery{
			SelectFields: []sq.Field{
				sq.Expr("1"),
			},
			FromTable: SITES,
			JoinTables: []sq.JoinTable{
				sq.Join(USERS, USERS.USER_ID.Eq(SITES.USER_ID)),
			},
			WherePredicate: sq.And(
				SITES.SITE_NAME.Eq(LOGINS.SITE_NAME),
				USERS.EMAIL.EqString(cmd.Email),
			),
		}),
	})
	if err != nil {
		return err
	}
	_, err = sq.Exec(tx, sq.DeleteQuery{
		Dialect:     cmd.Notebrew.Dialect,
		DeleteTable: SESSIONS,
		WherePredicate: sq.Exists(sq.SelectQuery{
			SelectFields: []sq.Field{
				sq.Expr("1"),
			},
			FromTable: USERS,
			WherePredicate: sq.And(
				USERS.USER_ID.Eq(SESSIONS.USER_ID),
				USERS.EMAIL.EqString(cmd.Email),
			),
		}),
	})
	if err != nil {
		return err
	}
	result, err := sq.Exec(tx, sq.UpdateQuery{
		Dialect:     cmd.Notebrew.Dialect,
		UpdateTable: USERS,
		Assignments: []sq.Assignment{
			USERS.PASSWORD_HASH.SetString(cmd.PasswordHash),
		},
		WherePredicate: USERS.EMAIL.EqString(cmd.Email),
	})
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.Stderr, "%d user updated\n", result.RowsAffected)
	return nil
}
