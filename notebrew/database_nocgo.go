//go:build !cgo

package main

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/bokwoon95/nb3"
	"modernc.org/sqlite"
)

func init() {
	// SQLite.
	nb3.RegisterDriver(nb3.Driver{
		Dialect:    "sqlite",
		DriverName: "sqlite",
		ErrorCode: func(err error) (errcode string) {
			var sqliteErr *sqlite.Error
			if errors.As(err, &sqliteErr) {
				return strconv.Itoa(int(sqliteErr.Code()))
			}
			return ""
		},
		PreprocessDSN: func(dsn string) (string, error) {
			before, after, _ := strings.Cut(dsn, "?")
			q, err := url.ParseQuery(after)
			if err != nil {
				return dsn, nil
			}
			hasPragma := make(map[string]bool)
			values := q["_pragma"]
			for _, value := range values {
				pragma, _, _ := strings.Cut(value, "(")
				hasPragma[pragma] = true
			}
			if !hasPragma["busy_timeout"] {
				q.Add("_pragma", "busy_timeout(10000)") // milliseconds
			}
			if !hasPragma["foreign_keys"] {
				q.Add("_pragma", "foreign_keys(ON)")
			}
			if !hasPragma["journal_mode"] {
				q.Add("_pragma", "journal_mode(WAL)")
			}
			if !hasPragma["synchronous"] {
				q.Add("_pragma", "synchronous(NORMAL)")
			}
			if !q.Has("_txlock") {
				q.Set("_txlock", "immediate")
			}
			query := strings.NewReplacer("%28", "(", "%29", ")").Replace(q.Encode())
			return before + "?" + query, nil
		},
	})
}
