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
	"io"
	"io/fs"
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
	case "static":
		nb.static(w, r, urlpath)
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
		nb.create(w, r, urlpath)
	case "update":
	case "delete":
	case "rename":
	case "assets":
	case "images":
	case "templates":
	case "posts":
	case "pages":
	default:
		http.NotFound(w, r)
	}
}

func (nb *Notebrew) login(w http.ResponseWriter, r *http.Request) {
	if nb.DB == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	err := r.ParseForm()
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case "GET":
		// If there is already a valid sessionToken, redirect user to the
		// dashboard instead.
		sessionTokenHash := nb.sessionTokenHash(r)
		if sessionTokenHash != nil {
			exists, err := sq.FetchExistsContext(r.Context(), nb.DB, sq.SelectQuery{
				Dialect:        nb.Dialect,
				SelectFields:   SelectOne,
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
			http.SetCookie(w, &http.Cookie{
				Path:     "/admin/login/",
				Name:     "responseCode",
				Value:    "",
				Secure:   nb.AdminDomain != "",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   -1,
			})
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
		buf.WriteTo(w)
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
		// Redirect user to the dashboard (or target).
		if target != "" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/admin/", http.StatusFound)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nb *Notebrew) logout(w http.ResponseWriter, r *http.Request) {
	if nb.DB == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
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
	if nb.DB == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
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

func (nb *Notebrew) static(w http.ResponseWriter, r *http.Request, urlpath string) {
	file, err := os.DirFS(".").Open(path.Join("static", urlpath))
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
	if nb.DB != nil {
		// If user does not have a sessionToken, redirect them to the login page.
		sessionTokenHash := nb.sessionTokenHash(r)
		if sessionTokenHash == nil {
			http.Redirect(w, r, "/admin/login/", http.StatusFound)
			return
		}
		// If user's sessionToken is not valid, redirect them to the login page.
		exists, err := sq.FetchExistsContext(r.Context(), nb.DB, sq.SelectQuery{
			Dialect:        nb.Dialect,
			SelectFields:   SelectOne,
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
		buf.WriteTo(w)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nb *Notebrew) resetpassword(w http.ResponseWriter, r *http.Request) {
	if nb.DB == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
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
		Dialect:        nb.Dialect,
		SelectFields:   SelectOne,
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
		var responseCode int
		if cookie, _ := r.Cookie("responseCode"); cookie != nil {
			responseCode, _ = strconv.Atoi(cookie.Value)
			http.SetCookie(w, &http.Cookie{
				Path:     "/admin/resetpassword/",
				Name:     "responseCode",
				Value:    "",
				Secure:   nb.AdminDomain != "",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   -1,
			})
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
		buf.WriteTo(w)
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
				SelectFields: SelectOne,
				FromTable:    Sites,
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
				SelectFields: SelectOne,
				FromTable:    Users,
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
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nb *Notebrew) create(w http.ResponseWriter, r *http.Request, urlpath string) {
	// POST /admin/create/post/
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
	if nb.DB != nil {
		// If user does not have a sessionToken, HTTP Unauthorized.
		sessionTokenHash := nb.sessionTokenHash(r)
		if sessionTokenHash == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// If user's sessionToken is not valid, HTTP Unauthorized.
		exists, err := sq.FetchExistsContext(r.Context(), nb.DB, sq.SelectQuery{
			Dialect:        nb.Dialect,
			SelectFields:   SelectOne,
			FromTable:      Sessions,
			WherePredicate: Sessions.SESSION_TOKEN_HASH.EqBytes(sessionTokenHash),
		})
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	// TODO: the path is just /create/ now. Anything else is 404.
	// TODO: or is it /admin/upload/?
	// TODO: /admin/create/post/, /admin/update/post/, /admin/upload/, /admin/delete/, /admin/rename/
	// The overwhelming factor is based on whether I can make the endpoints useful even with noscript.
	//
	// If it's a post, the first item must have the name "post", followed by
	// one or more names of "image". Any other string is an error. The response
	// is HTTP 302 (Found), together with a redirect link to the newly-created
	// page.
	//
	// If the first name is not "post", subsequent names are not allowed to
	// have either "post" or "image". The only names allowed in this mode must
	// either have a prefix of "templates/...", "pages/..." or "assets/...".
	// The response is HTTP 204 (No Content).
	//
	// "post": "...", "image": "...", "image": "..." => HTTP 302 (Found) /admin/posts/<postID>/
	// "templates/a/b/c": "...", "pages/d/e/f": "...", "assets/g/h/i.jpg": "..."
	segment, urlpath, _ := strings.Cut(strings.Trim(urlpath, "/"), "/")
	switch segment {
	case "post":
		segment, _, _ := strings.Cut(strings.Trim(urlpath, "/"), "/")
		if segment != "" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
		reader, err := r.MultipartReader()
		if err != nil {
			http.Error(w, callermsg(err), http.StatusInternalServerError)
			return
		}
		var postID string
		for i := 0; i < 100; i++ {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, callermsg(err), http.StatusInternalServerError)
				return
			}
			if part.FormName() == "content" {
				postID = strings.ToLower(ulid.Make().String())
				file, err := OpenWriter(nb.FS, path.Join("posts", postID+".md"))
				if err != nil {
					if errors.Is(err, ErrNotSupported) {
						http.Error(w, "Not Implemented", http.StatusNotImplemented)
						return
					}
					http.Error(w, callermsg(err), http.StatusInternalServerError)
					return
				}
				defer file.Close()
				_, err = io.Copy(file, part)
				if err != nil {
					http.Error(w, callermsg(err), http.StatusInternalServerError)
					return
				}
				err = part.Close()
				if err != nil {
					http.Error(w, callermsg(err), http.StatusInternalServerError)
					return
				}
				err = file.Close()
				if err != nil {
					http.Error(w, callermsg(err), http.StatusInternalServerError)
					return
				}
			}
			if postID != "" {
				break
			}
		}
		if postID == "" {
			http.Error(w, "Bad Request: content missing", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/admin/posts/"+postID+"/", http.StatusFound)
	case "page":
	case "template":
	case "asset":
	default:
		http.Error(w, "Bad Request", http.StatusBadRequest)
	}
}
