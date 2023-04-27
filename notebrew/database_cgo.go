//go:build cgo

package main

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/bokwoon95/nb3"
	"github.com/mattn/go-sqlite3"
)

func init() {
	// SQLite.
	nb3.RegisterDriver(nb3.Driver{
		Dialect:    "sqlite",
		DriverName: "sqlite3",
		ErrorCode: func(err error) (errcode string) {
			var sqliteErr sqlite3.Error
			if errors.As(err, &sqliteErr) {
				return strconv.Itoa(int(sqliteErr.ExtendedCode))
			}
			return ""
		},
		PreprocessDSN: func(dsn string) (string, error) {
			before, after, _ := strings.Cut(dsn, "?")
			q, err := url.ParseQuery(after)
			if err != nil {
				return dsn, nil
			}
			if !q.Has("_busy_timeout") && !q.Has("_timeout") {
				q.Set("_busy_timeout", "10000") // milliseconds
			}
			if !q.Has("_foreign_keys") && !q.Has("_fk") {
				q.Set("_foreign_keys", "ON")
			}
			if !q.Has("_journal_mode") && !q.Has("_journal") {
				q.Set("_journal_mode", "WAL")
			}
			if !q.Has("_synchronous") && !q.Has("_sync") {
				q.Set("_synchronous", "NORMAL")
			}
			if !q.Has("_txlock") {
				q.Set("_txlock", "immediate")
			}
			return before + "?" + q.Encode(), nil
		},
	})
}
