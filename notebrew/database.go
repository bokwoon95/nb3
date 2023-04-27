package main

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/bokwoon95/nb3"
	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

func init() {
	// Postgres.
	nb3.RegisterDriver(nb3.Driver{
		Dialect:    "postgres",
		DriverName: "postgres",
		ErrorCode: func(err error) (errcode string) {
			var pqerr *pq.Error
			if errors.As(err, &pqerr) {
				return string(pqerr.Code)
			}
			return ""
		},
		PreprocessDSN: func(dsn string) (string, error) {
			before, after, _ := strings.Cut(dsn, "?")
			q, err := url.ParseQuery(after)
			if err != nil {
				return dsn, nil
			}
			if !q.Has("sslmode") {
				q.Set("sslmode", "disable")
			}
			return before + "?" + q.Encode(), nil
		},
	})

	// MySQL.
	nb3.RegisterDriver(nb3.Driver{
		Dialect:    "mysql",
		DriverName: "mysql",
		ErrorCode: func(err error) (errcode string) {
			var mysqlerr *mysql.MySQLError
			if errors.As(err, &mysqlerr) {
				return strconv.FormatUint(uint64(mysqlerr.Number), 10)
			}
			return ""
		},
		PreprocessDSN: func(dsn string) (string, error) {
			if strings.HasPrefix(dsn, "mysql://") {
				u, err := url.Parse(dsn)
				if err != nil {
					dsn = strings.TrimPrefix(dsn, "mysql://")
				} else {
					var b strings.Builder
					b.Grow(len(dsn))
					if u.User != nil {
						username := u.User.Username()
						password, ok := u.User.Password()
						b.WriteString(username)
						if ok {
							b.WriteString(":" + password)
						}
					}
					if u.Host != "" {
						if b.Len() > 0 {
							b.WriteString("@")
						}
						b.WriteString("tcp(" + u.Host + ")")
					}
					b.WriteString("/" + strings.TrimPrefix(u.Path, "/"))
					if u.RawQuery != "" {
						b.WriteString("?" + u.RawQuery)
					}
					dsn = b.String()
				}
			}
			before, after, _ := strings.Cut(dsn, "?")
			q, err := url.ParseQuery(after)
			if err != nil {
				return dsn, nil
			}
			if !q.Has("allowAllFiles") {
				q.Set("allowAllFiles", "true")
			}
			if !q.Has("multiStatements") {
				q.Set("multiStatements", "true")
			}
			if !q.Has("parseTime") {
				q.Set("parseTime", "true")
			}
			return before + "?" + q.Encode(), nil
		},
	})

	// SQL Server.
	nb3.RegisterDriver(nb3.Driver{
		Dialect:    "sqlserver",
		DriverName: "sqlserver",
		ErrorCode: func(err error) (errcode string) {
			var mssqlErr mssql.Error
			if errors.As(err, &mssqlErr) {
				strconv.FormatInt(int64(mssqlErr.Number), 10)
			}
			return ""
		},
		PreprocessDSN: func(dsn string) (string, error) {
			u, err := url.Parse(dsn)
			if err != nil {
				return dsn, nil
			}
			if u.Path != "" {
				before, after, _ := strings.Cut(dsn, "?")
				q, err := url.ParseQuery(after)
				if err != nil {
					return dsn, nil
				}
				q.Set("database", u.Path[1:])
				dsn = strings.TrimSuffix(before, u.Path) + "?" + q.Encode()
			}
			return dsn, nil
		},
	})
}
