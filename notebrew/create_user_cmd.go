package main

import (
	"bufio"
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/bokwoon95/nb3"
	"github.com/bokwoon95/sq"
	"github.com/oklog/ulid/v2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type CreateUserCmd struct {
	Notebrew     *nb3.Notebrew
	Stderr       io.Writer
	Email        string
	DisplayName  string
	PasswordHash string
}

func CreateUserCommand(nb *nb3.Notebrew, args ...string) (*CreateUserCmd, error) {
	var cmd CreateUserCmd
	cmd.Notebrew = nb
	var displayNameProvided bool
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.StringVar(&cmd.Email, "email", "", "")
	flagset.Func("display-name", "", func(s string) error {
		cmd.DisplayName, displayNameProvided = s, true
		return nil
	})
	flagset.StringVar(&cmd.PasswordHash, "password-hash", "", "")
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
		Dialect:        cmd.Notebrew.Dialect,
		SelectFields:   []sq.Field{sq.Expr("1")},
		FromTable:      USERS,
		WherePredicate: USERS.EMAIL.EqString(cmd.Email),
	})
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("user already exists for email %s", cmd.Email)
	}

	if cmd.PasswordHash == "" {
		for {
			fmt.Print("Password (will be hidden from view): ")
			password, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return nil, err
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

	cmd.DisplayName = strings.TrimSpace(cmd.DisplayName)
	if !displayNameProvided {
		for {
			fmt.Print("Display Name: ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.DisplayName = strings.TrimSpace(text)
			break
		}
	}
	return &cmd, nil
}

func (cmd *CreateUserCmd) Run() error {
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	userID := ulid.Make()
	USERS := sq.New[nb3.USERS]("")
	result, err := sq.Exec(cmd.Notebrew.DB, sq.InsertQuery{
		Dialect:     cmd.Notebrew.Dialect,
		InsertTable: USERS,
		ColumnMapper: func(col *sq.Column) {
			col.SetUUID(USERS.USER_ID, userID)
			col.SetString(USERS.EMAIL, cmd.Email)
			col.SetString(USERS.DISPLAY_NAME, cmd.DisplayName)
			col.SetString(USERS.PASSWORD_HASH, cmd.PasswordHash)
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.Stderr, "%d user inserted\n", result.RowsAffected)
	if cmd.Notebrew.MultisiteMode != "" {
		return nil
	}
	siteID := ulid.Make()
	const siteName = ""
	SITES := sq.New[nb3.SITES]("")
	_, err = sq.Exec(cmd.Notebrew.DB, sq.InsertQuery{
		Dialect:     cmd.Notebrew.Dialect,
		InsertTable: SITES,
		InsertColumns: []sq.Field{
			SITES.SITE_ID,
			SITES.SITE_NAME,
			SITES.IS_CUSTOM_DOMAIN,
			SITES.USER_ID,
		},
		SelectQuery: sq.
			Select(
				sq.Value(siteID),
				sq.Value(siteName),
				sq.Value(false),
				sq.Select(USERS.USER_ID).From(USERS).Where(USERS.EMAIL.EqString(cmd.Email)),
			).
			Where(sq.NotExists(
				sq.SelectOne().From(SITES).Where(SITES.SITE_NAME.EqString(siteName)),
			)),
	})
	if err != nil {
		return err
	}
	return nil
}
