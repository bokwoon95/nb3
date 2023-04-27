package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bokwoon95/nb3"
	"github.com/bokwoon95/sq"
	"github.com/oklog/ulid/v2"
)

type CreateSiteCmd struct {
	Notebrew *nb3.Notebrew
	Stderr   io.Writer
	SiteName string
	Email    string
}

func CreateSiteCommand(nb *nb3.Notebrew, args ...string) (*CreateSiteCmd, error) {
	var cmd CreateSiteCmd
	cmd.Notebrew = nb
	var siteNameProvided bool
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("site-name", "", func(s string) error {
		cmd.SiteName, siteNameProvided = s, true
		return nil
	})
	flagset.StringVar(&cmd.Email, "email", "", "")
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

	cmd.SiteName = strings.TrimSpace(cmd.SiteName)
	if !siteNameProvided {
		for {
			fmt.Print("Site Name (only alphabets, numbers, dot and hyphen are allowed): ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.SiteName = strings.TrimSpace(text)
			break
		}
	}
	for _, char := range cmd.SiteName {
		if (char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			char == '.' || char == '-' {
			continue
		}
		return nil, fmt.Errorf("site name contains invalid characters: only alphabets, numbers, dot and hyphen are allowed")
	}

	SITES := sq.New[nb3.SITES]("")
	exists, err := sq.FetchExists(cmd.Notebrew.DB, sq.SelectQuery{
		Dialect:        cmd.Notebrew.Dialect,
		SelectFields:   []sq.Field{sq.Expr("1")},
		FromTable:      SITES,
		WherePredicate: SITES.SITE_NAME.EqString(cmd.SiteName),
	})
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("site already exists")
	}

	cmd.Email = strings.TrimSpace(cmd.Email)
	if cmd.Email == "" {
		for {
			fmt.Print("Email (owner of the site): ")
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
	exists, err = sq.FetchExists(cmd.Notebrew.DB, sq.SelectQuery{
		Dialect:        cmd.Notebrew.Dialect,
		SelectFields:   []sq.Field{sq.Expr("1")},
		FromTable:      USERS,
		WherePredicate: USERS.EMAIL.EqString(cmd.Email),
	})
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no such user with email %s", cmd.Email)
	}

	return &cmd, nil
}

func (cmd *CreateSiteCmd) Run() error {
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	siteID := ulid.Make()
	SITES, USERS := sq.New[nb3.SITES](""), sq.New[nb3.USERS]("")
	results, err := sq.Exec(cmd.Notebrew.DB, sq.InsertQuery{
		Dialect:     cmd.Notebrew.Dialect,
		InsertTable: SITES,
		ColumnMapper: func(col *sq.Column) {
			col.SetUUID(SITES.SITE_ID, siteID)
			col.SetString(SITES.SITE_NAME, cmd.SiteName)
			col.SetBool(SITES.IS_CUSTOM_DOMAIN, strings.Contains(cmd.SiteName, "."))
			col.Set(SITES.USER_ID, sq.SelectQuery{
				SelectFields:   []sq.Field{USERS.USER_ID},
				FromTable:      USERS,
				WherePredicate: USERS.EMAIL.EqString(cmd.Email),
			})
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.Stderr, "%d site inserted\n", results.RowsAffected)
	return nil
}
