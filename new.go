package nb3

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/sq"
	"github.com/caddyserver/certmagic"
)

func New(fsys fs.FS) (*Notebrew, error) {
	nb := &Notebrew{
		FS:        fsys,
		ErrorCode: func(error) string { return "" },
	}

	// Read from address.txt.
	var address string
	file, err := nb.FS.Open("address.txt")
	if errors.Is(err, fs.ErrNotExist) {
		address = ":6444"
	} else if err != nil {
		return nil, err
	} else {
		defer file.Close()
		b, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}
		file.Close()
		address = strings.TrimSpace(string(b))
	}
	if strings.HasPrefix(address, ":") {
		// If address starts with ":", it's a localhost port.
		nb.Port, err = strconv.Atoi(address[1:])
		if err != nil {
			return nil, fmt.Errorf("address.txt: %q is not a valid port", address)
		}
	} else {
		// Make sure address is not empty.
		if address == "" {
			return nil, fmt.Errorf("address.txt: address cannot be empty")
		}
		nb.AdminDomain, nb.ContentDomain, _ = strings.Cut(address, "\n")
		nb.ContentDomain = strings.TrimSpace(nb.ContentDomain)
		if strings.Contains(nb.ContentDomain, "\n") {
			return nil, fmt.Errorf("address.txt: too many lines, maximum 2")
		}
		if nb.ContentDomain == "" {
			nb.ContentDomain = nb.AdminDomain
		}
		// Validate that domain only contains characters [a-zA-Z0-9.-].
		for _, char := range nb.AdminDomain {
			if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '.' || char == '-' {
				continue
			}
			return nil, fmt.Errorf("address.txt: invalid domain name %q: only alphabets, numbers, dot and hyphen are allowed", address)
		}
		for _, char := range nb.ContentDomain {
			if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '.' || char == '-' {
				continue
			}
			return nil, fmt.Errorf("address.txt: invalid domain name %q: only alphabets, numbers, dot and hyphen are allowed", address)
		}
	}

	// Read from multisite.txt.
	file, err = nb.FS.Open("multisite.txt")
	if errors.Is(err, fs.ErrNotExist) {
		nb.MultisiteMode = ""
	} else if err != nil {
		return nil, err
	} else {
		defer file.Close()
		b, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}
		file.Close()
		nb.MultisiteMode = strings.ToLower(string(b))
		if nb.MultisiteMode != "subdomain" && nb.MultisiteMode != "subdirectory" {
			return nil, fmt.Errorf("invalid multisite mode %q", string(b))
		}
	}

	// Read from database.txt.
	var dsn string
	file, err = nb.FS.Open("database.txt")
	if errors.Is(err, fs.ErrNotExist) {
		if nb.AdminDomain != "" {
			// If database.txt doesn't exist but we are serving a live site, we
			// have to create a database. In this case, fall back to an SQLite
			// database.
			nb.Dialect = "sqlite"
		}
	} else if err != nil {
		return nil, err
	} else {
		defer file.Close()
		b, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}
		file.Close()
		dsn = strings.TrimSpace(string(b))
		// Determine the database dialect from the dsn.
		if dsn == "sqlite" {
			nb.Dialect = "sqlite"
		} else if strings.HasPrefix(dsn, "postgres://") {
			nb.Dialect = "postgres"
		} else if strings.HasPrefix(dsn, "mysql://") {
			nb.Dialect = "mysql"
		} else if strings.HasPrefix(dsn, "sqlserver://") {
			nb.Dialect = "sqlserver"
		} else if strings.Contains(dsn, "@tcp(") || strings.Contains(dsn, "@unix(") {
			nb.Dialect = "mysql"
		} else if dsn != "" {
			return nil, fmt.Errorf("database.txt: unknown dsn %q", dsn)
		}
	}
	if nb.Dialect == "sqlserver" {
		return nil, fmt.Errorf("database.txt: sqlserver is not supported")
	}
	if nb.Dialect == "sqlite" {
		// SQLite databases can only be created by giving it a filepath on the
		// current system. Check if we can convert srv.fs into a filepath
		// string, then check if it is a valid directory. If it is, we can
		// create an SQLite database there.
		dir, err := filepath.Abs(fmt.Sprint(nb.FS))
		if err != nil {
			return nil, fmt.Errorf("unable to create DB")
		}
		fileinfo, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("unable to create DB")
		}
		if !fileinfo.IsDir() {
			return nil, fmt.Errorf("unable to create DB")
		}
		dsn = filepath.Join(dir, "notebrew.db")
	}
	if dsn != "" {
		var driverName string
		// Set a default driverName depending on the dialect.
		switch nb.Dialect {
		case "sqlite":
			driverName = "sqlite3"
		case "postgres":
			driverName = "postgres"
		case "mysql":
			driverName = "mysql"
		case "sqlserver":
			driverName = "sqlserver"
		}
		// Check if the user registered any driverName/dsn overrides for the
		// dialect.
		dbDriversMu.RLock()
		d := dbDrivers[nb.Dialect]
		dbDriversMu.RUnlock()
		if d.DriverName != "" {
			driverName = d.DriverName
		}
		if d.PreprocessDSN != nil {
			dsn, err = d.PreprocessDSN(dsn)
			if err != nil {
				return nil, err
			}
		} else {
			if nb.Dialect == "sqlite" {
				if strings.HasPrefix(dsn, "sqlite3:") {
					dsn = strings.TrimPrefix(strings.TrimPrefix(dsn, "sqlite3:"), "//")
				} else if strings.HasPrefix(dsn, "sqlite:") {
					dsn = strings.TrimPrefix(strings.TrimPrefix(dsn, "sqlite:"), "//")
				}
			} else if nb.Dialect == "mysql" {
				dsn = strings.TrimPrefix(dsn, "mysql://")
			}
		}
		if d.ErrorCode != nil {
			nb.ErrorCode = d.ErrorCode
		}
		// Open the database using the driverName and dsn.
		nb.DB, err = sql.Open(driverName, dsn)
		if err != nil {
			return nil, err
		}
		err = automigrate(nb.Dialect, nb.DB)
		if err != nil {
			return nil, err
		}
		if nb.AdminDomain != "" {
			nb.Port = 443
		}
	}

	// posts/ images/ pages/ templates/ assets/
	// posts | pages
	_ = MkdirAll(nb.FS, "posts", 0755)
	_ = MkdirAll(nb.FS, "images", 0755)
	_ = MkdirAll(nb.FS, "pages", 0755)
	_ = MkdirAll(nb.FS, "templates", 0755)
	_ = MkdirAll(nb.FS, "assets", 0755)
	if nb.MultisiteMode != "" {
		sites, err := sq.FetchAll(sq.Log(nb.DB), sq.SelectQuery{
			Dialect:   nb.Dialect,
			FromTable: Sites,
		}, func(row *sq.Row) (result struct {
			SiteName       string
			IsCustomDomain bool
		}) {
			result.SiteName = row.StringField(Sites.SITE_NAME)
			result.IsCustomDomain = row.BoolField(Sites.IS_CUSTOM_DOMAIN)
			return result
		})
		if err != nil {
			return nil, err
		}
		for _, site := range sites {
			siteName := site.SiteName
			if !site.IsCustomDomain {
				siteName = "~" + siteName
			}
			_ = MkdirAll(nb.FS, path.Join(siteName, "posts"), 0755)
			_ = MkdirAll(nb.FS, path.Join(siteName, "images"), 0755)
			_ = MkdirAll(nb.FS, path.Join(siteName, "pages"), 0755)
			_ = MkdirAll(nb.FS, path.Join(siteName, "templates"), 0755)
			_ = MkdirAll(nb.FS, path.Join(siteName, "assets"), 0755)
		}
	}

	return nb, nil
}

func (nb *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	addr, _ := getIP(r)
	userAgent := r.UserAgent()
	scheme := "http://"
	if r.TLS != nil {
		scheme = "https://"
	}
	_, _, _ = scheme, addr, userAgent
	log.Println(fmt.Sprintf("%-4s", r.Method), r.URL.Path)

	// Clean the path and redirect if necessary.
	if r.Method == "GET" {
		cleanedPath := path.Clean(r.URL.Path)
		if cleanedPath != "/" && path.Ext(cleanedPath) == "" {
			cleanedPath += "/"
		}
		if cleanedPath != r.URL.Path {
			uri := *r.URL
			uri.Path = cleanedPath
			http.Redirect(w, r, uri.String(), http.StatusMovedPermanently)
			return
		}
	}

	// Determine the sitename from the incoming request.
	var sitename string
	segment, urlpath, _ := strings.Cut(strings.Trim(r.URL.Path, "/"), "/")
	if nb.ContentDomain != "" {
		if nb.MultisiteMode == "subdomain" {
			if strings.HasSuffix(r.Host, nb.ContentDomain) {
				sitename = strings.TrimSuffix(strings.TrimSuffix(r.Host, nb.ContentDomain), ".")
			} else if r.Host != nb.AdminDomain {
				sitename = r.Host
			}
		} else if nb.MultisiteMode == "subdirectory" {
			if strings.HasSuffix(r.Host, nb.ContentDomain) {
				if strings.HasPrefix(segment, "~") {
					sitename = strings.TrimPrefix(segment, "~")
					segment, urlpath, _ = strings.Cut(strings.Trim(urlpath, "/"), "/")
				}
			} else if r.Host != nb.AdminDomain {
				sitename = r.Host
			}
		}
	}

	// nb.admin()
	// nb.login()
	// nb.logout()
	// nb.resetpassword()
	// nb.create()
	// nb.update()
	// nb.delete()
	// nb.rename()
	// nb.templates()
	// nb.static()
	// nb.images()
	// nb.pages()
	// nb.posts()
	// nb.notes()
	// nb.base() // nb.render() is used to render stuff from an io.Reader (it closes the reader if it implements Close())

	switch segment {
	case "admin":
		nb.admin(w, r, sitename, urlpath)
	case "assets", "images":
		nb.serveUserFile(w, r, sitename, path.Join(segment, urlpath))
	case "posts":
		// nb.posts(w, r, sitename, urlpath)
	default:
		// nb.base(w, r, sitename, urlpath)
		// w.Write([]byte("<!DOCTYPE html><title>notebrew</title><h1>Hello World!</h1>"))
		tmpl, err := template.ParseFS(os.DirFS("."), "html/default.html")
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, map[string]any{})
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		buf.WriteTo(w)
	}
}

func (nb *Notebrew) NewServer() (*http.Server, error) {
	server := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         "localhost:" + strconv.Itoa(nb.Port),
		ErrorLog:     log.New(io.Discard, "", 0),
		Handler:      nb,
	}
	if nb.AdminDomain != "" {
		server.Addr = ":443"
		certConfig := certmagic.NewDefault()
		domainNames := make([]string, 0, 3)
		domainNames = append(domainNames, nb.AdminDomain)
		if nb.ContentDomain != "" && nb.ContentDomain != nb.AdminDomain {
			domainNames = append(domainNames, nb.ContentDomain)
		}
		if nb.MultisiteMode == "subdomain" {
			if certmagic.DefaultACME.DNS01Solver == nil && certmagic.DefaultACME.CA == certmagic.LetsEncryptProductionCA {
				return nil, fmt.Errorf("DNS-01 solver not configured, cannot use subdomains")
			}
			domainNames = append(domainNames, "*."+nb.ContentDomain)
		}
		fmt.Println("domainNames:", domainNames)
		err := certConfig.ManageAsync(context.Background(), domainNames)
		if err != nil {
			return nil, err
		}
		server.TLSConfig = certConfig.TLSConfig()
		server.TLSConfig.NextProtos = []string{"h2", "http/1.1", "acme-tls/1"}
	}
	return server, nil
}

func (nb *Notebrew) Close() error {
	if nb.DB == nil {
		return nil
	}
	if nb.Dialect == "sqlite" {
		nb.DB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
	}
	return nb.DB.Close()
}

func getIP(r *http.Request) (string, error) {
	//Get IP from the X-REAL-IP header
	ip := r.Header.Get("X-REAL-IP")
	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}

	//Get IP from X-FORWARDED-FOR header
	ips := r.Header.Get("X-FORWARDED-FOR")
	splitIps := strings.Split(ips, ",")
	for _, ip := range splitIps {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return ip, nil
		}
	}

	//Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}
	return "", fmt.Errorf("No valid ip found")
}
