package nb3

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/sq"
	"github.com/oklog/ulid/v2"
	"golang.org/x/crypto/bcrypt"
)

func (nb *Notebrew) admin(w http.ResponseWriter, r *http.Request, sitename string, urlpath string) {
	segment, urlpath, _ := strings.Cut(strings.Trim(urlpath, "/"), "/")
	if sitename != "" {
		switch segment {
		case "login":
			nb.consumeLoginToken(w, r, sitename)
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
		return
	}

	switch segment {
	case "":
		nb.dashboard(w, r)
	case "assets":
		nb.assets(w, r, urlpath)
	case "login":
		segment, _, _ := strings.Cut(strings.Trim(urlpath, "/"), "/")
		if segment != "" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		nb.login(w, r)
	case "logout":
		segment, _, _ := strings.Cut(strings.Trim(urlpath, "/"), "/")
		if segment != "" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		nb.logout(w, r)
	case "resetpassword":
		segment, _, _ := strings.Cut(strings.Trim(urlpath, "/"), "/")
		if segment != "" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		nb.resetpassword(w, r)
	case "create":
	case "update":
	case "delete":
	case "rename":
	case "static":
	case "images":
	case "templates":
	case "posts":
	case "pages":
	case "notes":
	default:
		http.NotFound(w, r)
	}
}

func (nb *Notebrew) login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case "GET":
		// Reset the responseCode.
		http.SetCookie(w, &http.Cookie{
			Path:     "/admin/login/",
			Name:     "responseCode",
			Value:    "",
			Secure:   nb.AdminDomain != "",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		// If there is already a valid sessionToken, redirect user to the
		// dashboard instead.
		sessionTokenHash := nb.sessionTokenHash(r)
		if sessionTokenHash != nil {
			exists, err := sq.FetchExistsContext(r.Context(), nb.DB, sq.SelectQuery{
				Dialect: nb.Dialect,
				SelectFields: []sq.Field{
					sq.Expr("1"),
				},
				FromTable:      Sessions,
				WherePredicate: Sessions.SESSION_TOKEN_HASH.EqBytes(sessionTokenHash),
			})
			if err != nil {
				http.Error(w, callermsg(err), http.StatusInternalServerError)
				return
			}
			if exists {
				http.Redirect(w, r, "/admin/", http.StatusFound)
				return
			}
		}
		var responseCode int
		cookie, _ := r.Cookie("responseCode")
		if cookie != nil {
			responseCode, _ = strconv.Atoi(cookie.Value)
		}
		var target string
		value := r.FormValue("target")
		if strings.HasPrefix(value, "/admin/") {
			target = value
		}
		// Render html/login.html.
		tmpl, err := template.ParseFS(os.DirFS("."), "html/login.html")
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, map[string]any{
			"responseCode": responseCode,
			"target":       target,
		})
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		_, err = buf.WriteTo(w)
		if err != nil {
			log.Println(err)
		}
	case "POST":
		email := r.PostForm.Get("email")
		password := r.PostForm.Get("password")
		var target string
		value := r.PostForm.Get("target")
		if strings.HasPrefix(value, "/admin/") {
			target = value
		}
		// Get the user info for the given email.
		result, err := sq.FetchOneContext(r.Context(), nb.DB, sq.SelectQuery{
			Dialect:        nb.Dialect,
			FromTable:      Users,
			WherePredicate: Users.EMAIL.EqString(email),
		}, func(row *sq.Row) (result struct {
			UserID       ulid.ULID
			PasswordHash string
		}) {
			row.UUIDField(&result.UserID, Users.USER_ID)
			result.PasswordHash = row.StringField(Users.PASSWORD_HASH)
			return result
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		// Validate the user's password.
		err = bcrypt.CompareHashAndPassword([]byte(result.PasswordHash), []byte(password))
		if err != nil {
			http.SetCookie(w, &http.Cookie{
				Path:     "/admin/login/",
				Name:     "responseCode",
				Value:    "1",
				Secure:   nb.AdminDomain != "",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			var query string
			if target != "" {
				values := make(url.Values)
				values.Set("target", target)
				query = "?" + values.Encode()
			}
			http.Redirect(w, r, "/admin/login/"+query, http.StatusFound)
			return
		}
		// Generate the sessionToken.
		var sessionToken [8 + 16]byte
		binary.BigEndian.PutUint64(sessionToken[:8], uint64(time.Now().Unix()))
		_, err = rand.Read(sessionToken[8:])
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		// Save the sessionTokenHash to the database.
		checksum := sha256.Sum256([]byte(sessionToken[8:]))
		var sessionTokenHash [8 + sha256.Size]byte
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		_, err = sq.ExecContext(r.Context(), nb.DB, sq.InsertQuery{
			Dialect:     nb.Dialect,
			InsertTable: Sessions,
			ColumnMapper: func(col *sq.Column) {
				col.SetBytes(Sessions.SESSION_TOKEN_HASH, sessionTokenHash[:])
				col.SetUUID(Sessions.USER_ID, result.UserID)
			},
		})
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		// Write the sessionToken to the session cookie.
		http.SetCookie(w, &http.Cookie{
			Path:     "/",
			Name:     "session",
			Value:    strings.TrimLeft(hex.EncodeToString(sessionToken[:]), "0"),
			Secure:   nb.AdminDomain != "",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		// Redirect user to the dashboard.
		http.Redirect(w, r, "/admin/", http.StatusFound)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nb *Notebrew) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// Get the user's sessionTokenHash.
	sessionTokenHash := nb.sessionTokenHash(r)
	if sessionTokenHash == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// Delete their sessionTokenHash from the database.
	_, err := sq.ExecContext(r.Context(), nb.DB, sq.DeleteQuery{
		Dialect:        nb.Dialect,
		DeleteTable:    Sessions,
		WherePredicate: Sessions.SESSION_TOKEN_HASH.EqBytes(sessionTokenHash),
	})
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (nb *Notebrew) consumeLoginToken(w http.ResponseWriter, r *http.Request, sitename string) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseForm()
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	// Make sure token is not empty.
	if r.Form.Get("token") == "" {
		http.Error(w, "token invalid", http.StatusBadRequest)
		return
	}
	// Decode the loginToken hexadecimal string to bytes.
	loginToken, err := hex.DecodeString(fmt.Sprintf("%048s", r.Form.Get("token")))
	if err != nil {
		http.Error(w, "token invalid", http.StatusBadRequest)
		return
	}
	// Get login info for the give loginToken.
	result, err := sq.FetchOneContext(r.Context(), nb.DB, sq.SelectQuery{
		Dialect:        nb.Dialect,
		FromTable:      Logins,
		WherePredicate: Logins.LOGIN_TOKEN.EqBytes(loginToken),
	}, func(row *sq.Row) (result struct {
		SessionToken []byte
		SiteName     string
	}) {
		result.SessionToken = row.BytesField(Logins.SESSION_TOKEN)
		result.SiteName = row.StringField(Logins.SITE_NAME)
		return result
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "token invalid", http.StatusBadRequest)
			return
		}
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	// Make sure the loginToken's sitename matches the current sitename (to
	// prevent users from logging into other sites using their own
	// loginTokens).
	if result.SiteName != sitename {
		http.Error(w, "token invalid", http.StatusBadRequest)
		return
	}
	// Delete the loginToken from the database.
	_, err = sq.ExecContext(r.Context(), nb.DB, sq.DeleteQuery{
		Dialect:        nb.Dialect,
		DeleteTable:    Logins,
		WherePredicate: Logins.LOGIN_TOKEN.EqBytes(loginToken),
	})
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	// Set the sessionToken for the current domain.
	http.SetCookie(w, &http.Cookie{
		Path:     "/",
		Name:     "session",
		Value:    strings.TrimLeft(hex.EncodeToString(result.SessionToken[:]), "0"),
		Secure:   nb.AdminDomain != "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	// Redirect user to their target.
	target := "/admin/"
	value := r.Form.Get("target")
	if strings.HasPrefix(value, "/admin/") {
		target = value
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (nb *Notebrew) assets(w http.ResponseWriter, r *http.Request, urlpath string) {
	file, err := os.DirFS(".").Open(path.Join("assets", urlpath))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	serveFile(w, r, file)
}

func (nb *Notebrew) dashboard(w http.ResponseWriter, r *http.Request) {
	// If user does not have a sessionToken, redirect them to the login page.
	sessionTokenHash := nb.sessionTokenHash(r)
	if sessionTokenHash == nil {
		http.Redirect(w, r, "/admin/login/", http.StatusFound)
		return
	}
	// If user's sessionToken is not valid, redirect them to the login page.
	exists, err := sq.FetchExistsContext(r.Context(), nb.DB, sq.SelectQuery{
		Dialect: nb.Dialect,
		SelectFields: []sq.Field{
			sq.Expr("1"),
		},
		FromTable:      Sessions,
		WherePredicate: Sessions.SESSION_TOKEN_HASH.EqBytes(sessionTokenHash),
	})
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Redirect(w, r, "/admin/login/", http.StatusFound)
		return
	}
	switch r.Method {
	case "GET":
		// Render html/dashboard.html.
		tmpl, err := template.ParseFS(os.DirFS("."), "html/dashboard.html")
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
		_, err = buf.WriteTo(w)
		if err != nil {
			log.Println(err)
		}
	case "POST":
	}
}

func (nb *Notebrew) resetpassword(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	// Make sure token is not empty.
	if r.Form.Get("token") == "" {
		http.Error(w, "token invalid", http.StatusBadRequest)
		return
	}
	// Decode the resetToken hexadecimal string to bytes and derive the
	// resetTokenHash from it.
	resetToken, err := hex.DecodeString(fmt.Sprintf("%048s", r.Form.Get("token")))
	if err != nil {
		http.Error(w, "token invalid", http.StatusBadRequest)
		return
	}
	checksum := sha256.Sum256([]byte(resetToken[8:]))
	var resetTokenHash [8 + sha256.Size]byte
	copy(resetTokenHash[:8], resetToken[:8])
	copy(resetTokenHash[8:], checksum[:])
	// Make sure the resetTokenHash exists in the database.
	exists, err := sq.FetchExistsContext(r.Context(), nb.DB, sq.SelectQuery{
		Dialect: nb.Dialect,
		SelectFields: []sq.Field{
			sq.Expr("1"),
		},
		FromTable:      Users,
		WherePredicate: Users.RESET_TOKEN_HASH.EqBytes(resetTokenHash[:]),
	})
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "token invalid", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case "GET":
		// Reset the responseCode.
		http.SetCookie(w, &http.Cookie{
			Path:     "/admin/resetpassword/",
			Name:     "responseCode",
			Value:    "",
			Secure:   nb.AdminDomain != "",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		var responseCode int
		if cookie, _ := r.Cookie("responseCode"); cookie != nil {
			responseCode, _ = strconv.Atoi(cookie.Value)
		}
		// Render html/resetpassword.html.
		tmpl, err := template.ParseFS(os.DirFS("."), "html/resetpassword.html")
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, map[string]any{
			"responseCode": responseCode,
			"token":        strings.TrimLeft(hex.EncodeToString(resetToken), "0"),
		})
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		_, err = buf.WriteTo(w)
		if err != nil {
			log.Println(err)
		}
	case "POST":
		// Make sure the password is at least 8 characters.
		password := r.PostForm.Get("password")
		if utf8.RuneCountInString(password) < 8 {
			http.SetCookie(w, &http.Cookie{
				Path:     "/admin/resetpassword/",
				Name:     "responseCode",
				Value:    "1",
				Secure:   nb.AdminDomain != "",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			values := make(url.Values)
			values.Set("token", strings.TrimLeft(hex.EncodeToString(resetToken), "0"))
			http.Redirect(w, r, "/admin/resetpassword/?"+values.Encode(), http.StatusFound)
			return
		}
		// Make sure the confirmPassword value matches the password.
		confirmPassword := r.PostForm.Get("confirm-password")
		if confirmPassword != password {
			http.SetCookie(w, &http.Cookie{
				Path:     "/admin/resetpassword/",
				Name:     "responseCode",
				Value:    "2",
				Secure:   nb.AdminDomain != "",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			values := make(url.Values)
			values.Set("token", strings.TrimLeft(hex.EncodeToString(resetToken), "0"))
			http.Redirect(w, r, "/admin/resetpassword/?"+values.Encode(), http.StatusFound)
			return
		}
		// Generate the passwordHash.
		b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		passwordHash := string(b)
		// Begin a database transaction (we need to write to multiple tables).
		tx, err := nb.DB.Begin()
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()
		// Delete existing login tokens related to the user.
		_, err = sq.ExecContext(r.Context(), tx, sq.DeleteQuery{
			Dialect:     nb.Dialect,
			DeleteTable: Logins,
			WherePredicate: sq.Exists(sq.SelectQuery{
				SelectFields: []sq.Field{
					sq.Expr("1"),
				},
				FromTable: Sites,
				JoinTables: []sq.JoinTable{
					sq.Join(Users, Users.USER_ID.Eq(Sites.USER_ID)),
				},
				WherePredicate: sq.And(
					Sites.SITE_NAME.Eq(Logins.SITE_NAME),
					Users.RESET_TOKEN_HASH.EqBytes(resetTokenHash[:]),
				),
			}),
		})
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		// Delete existing session tokens related to the user.
		_, err = sq.ExecContext(r.Context(), tx, sq.DeleteQuery{
			Dialect:     nb.Dialect,
			DeleteTable: Sessions,
			WherePredicate: sq.Exists(sq.SelectQuery{
				SelectFields: []sq.Field{
					sq.Expr("1"),
				},
				FromTable: Users,
				WherePredicate: sq.And(
					Users.USER_ID.Eq(Sessions.USER_ID),
					Users.RESET_TOKEN_HASH.EqBytes(resetTokenHash[:]),
				),
			}),
		})
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		// Update the user's password hash and delete their reset token.
		_, err = sq.ExecContext(r.Context(), tx, sq.UpdateQuery{
			Dialect:     nb.Dialect,
			UpdateTable: Users,
			Assignments: []sq.Assignment{
				Users.PASSWORD_HASH.SetString(passwordHash),
				Users.RESET_TOKEN_HASH.Set(nil),
			},
			WherePredicate: Users.RESET_TOKEN_HASH.EqBytes(resetToken),
		})
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		// Commit the database transaction.
		err = tx.Commit()
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		// Redirect the user to the login page.
		http.SetCookie(w, &http.Cookie{
			Path:     "/admin/login/",
			Name:     "responseCode",
			Value:    "2",
			Secure:   nb.AdminDomain != "",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/admin/login/", http.StatusFound)
	}
}
