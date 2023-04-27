package nb3

import (
	"database/sql"
	"embed"
	"io"
	"os"

	"github.com/bokwoon95/sq"
	"github.com/bokwoon95/sqddl/ddl"
)

//go:embed tables.go
var migrationFS embed.FS

func automigrate(dialect string, db *sql.DB) error {
	if db == nil {
		return nil
	}
	automigrateCmd := &ddl.AutomigrateCmd{
		DB:             db,
		Dialect:        dialect,
		DirFS:          migrationFS,
		Filenames:      []string{"tables.go"},
		DropObjects:    true,
		AcceptWarnings: true,
		DryRun:         true,
		Stdout:         os.Stderr,
	}
	err := automigrateCmd.Run()
	if err != nil {
		return err
	}
	automigrateCmd.DryRun = false
	automigrateCmd.Stderr = io.Discard
	err = automigrateCmd.Run()
	if err != nil {
		return err
	}
	return nil
}

var Users = sq.New[USERS]("")

type USERS struct {
	sq.TableStruct
	USER_ID          sq.UUIDField   `ddl:"primarykey"`
	EMAIL            sq.StringField `ddl:"notnull len=255 unique"`
	PASSWORD_HASH    sq.StringField `ddl:"notnull len=255"`
	DISPLAY_NAME     sq.StringField `ddl:"len=255"`
	RESET_TOKEN_HASH sq.BinaryField `ddl:"mysql:type=BINARY(40) unique"`
}

var Sites = sq.New[SITES]("")

type SITES struct {
	sq.TableStruct
	SITE_ID          sq.UUIDField    `ddl:"primarykey"`
	SITE_NAME        sq.StringField  `ddl:"notnull len=255 unique"`
	IS_CUSTOM_DOMAIN sq.BooleanField `ddl:"notnull"`
	USER_ID          sq.UUIDField    `ddl:"notnull references={users onupdate=cascade index}"`
}

var Sessions = sq.New[SESSIONS]("")

// DELETE FROM logins WHERE EXISTS (SELECT 1 FROM sites JOIN users ON users.user_id = sites.user_id WHERE sites.site_name = logins.site_name AND users.reset_token_hash = ?)

// DELETE FROM sessions WHERE EXISTS (SELECT 1 FROM users WHERE users.user_id = sessions.user_id AND users.reset_token_hash = ?)

type SESSIONS struct {
	sq.TableStruct
	SESSION_TOKEN_HASH sq.BinaryField `ddl:"mysql:type=BINARY(40) primarykey"`
	USER_ID            sq.UUIDField   `ddl:"notnull references={users onupdate=cascade index}"`
}

var Logins = sq.New[LOGINS]("")

type LOGINS struct {
	sq.TableStruct
	LOGIN_TOKEN   sq.BinaryField `ddl:"primarykey mysql:type=BINARY(24)"`
	SESSION_TOKEN sq.BinaryField `ddl:"mysql:type=BINARY(24) notnull"`
	SITE_NAME     sq.StringField `ddl:"notnull len=255 references={sites onupdate=cascade index}"`
}
