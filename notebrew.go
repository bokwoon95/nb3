package nb3

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template/parse"
)

// ErrNotSupported indicates that a feature is not supported.
//
// It is returned by the functions OpenWriter, RemoveAll and WalkDir to
// indicate that the underlying fs.FS does not support the method.
var ErrNotSupported = errors.New("feature not supported")

// Notebrew represents a notebrew instance.
type Notebrew struct {
	// FS is the file system associated with the notebrew instance.
	FS fs.FS

	// DB is the database associated with the notebrew instance.
	DB *sql.DB

	// Dialect is dialect of the database. Only sqlite, postgres and mysql
	// databases are supported.
	Dialect string

	AdminDomain string

	ContentDomain string

	MultisiteMode string // subdomain | subdirectory

	// Port indicates which TCP port notebrew is listening to. If operating in
	// localhost mode, this can be any number between 1-65535. If connected to
	// the internet i.e. RootDomain is non-empty, the port is always 443.
	Port int

	// ErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or if no underlying
	// implementation is provided, ErrorCode should return an empty string.
	ErrorCode func(error) string
}

// WriteFS is the interface implemented by a file system that can be written
// to.
type WriteFS interface {
	fs.FS

	// OpenWriter opens an io.WriteCloser that represents an instance of a file
	// that can be written to. If the file doesn't exist, it should be created.
	OpenWriter(name string) (io.WriteCloser, error)
}

type MkdirAllFS interface {
	fs.FS

	MkdirAll(path string, perm fs.FileMode) error
}

// RemoveAllFS is the interface implemented by a file system that can remove
// files.
type RemoveAllFS interface {
	fs.FS

	// RemoveAll removes all files with prefix matching the path. If there are
	// no files matching the path, RemoveAll returns nil.
	RemoveAll(path string) error
}

// WalkDirFS is the interface implemented by a file system that provides an
// optimized implementation of WalkDir.
type WalkDirFS interface {
	fs.FS

	// WalkDir walks the file tree rooted at root, calling fn for each file or
	// directory in the tree, including root.
	WalkDir(root string, fn fs.WalkDirFunc) error
}

// OpenWriter opens an io.WriteCloser from the file system that represents an
// instance of a file that can be written to. If the file doesn't exist, it
// should be created.
func OpenWriter(fsys fs.FS, name string) (io.WriteCloser, error) {
	if fsys, ok := fsys.(WriteFS); ok {
		return fsys.OpenWriter(name)
	}
	return nil, ErrNotSupported
}

func MkdirAll(fsys fs.FS, path string, perm fs.FileMode) error {
	if fsys, ok := fsys.(MkdirAllFS); ok {
		return fsys.MkdirAll(path, perm)
	}
	return ErrNotSupported
}

// RemoveAll removes all files from the file system with prefix matching the
// path. If there are no files matching the path, RemoveAll returns nil.
func RemoveAll(fsys fs.FS, path string) error {
	if fsys, ok := fsys.(RemoveAllFS); ok {
		return fsys.RemoveAll(path)
	}
	return ErrNotSupported
}

// WalkDir walks the file tree rooted at root, calling fn for each file or
// directory in the tree, including root.
func WalkDir(fsys fs.FS, root string, fn fs.WalkDirFunc) error {
	if fsys, ok := fsys.(WalkDirFS); ok {
		return fsys.WalkDir(root, fn)
	}
	err := fs.WalkDir(fsys, root, fn)
	if err != nil {
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) && pathErr.Op == "readdir" && pathErr.Err.Error() == "not implemented" {
			return ErrNotSupported
		}
		return err
	}
	return nil
}

var (
	dbDriversMu sync.RWMutex
	dbDrivers   = make(map[string]Driver)
)

// Driver represents the capabilities of the underlying database driver for a
// particular dialect. It is not necessary to implement all fields.
type Driver struct {
	// (Required) Dialect is the database dialect. Possible values: "sqlite", "postgres",
	// "mysql".
	Dialect string

	// (Required) DriverName is the driverName to be used with sql.Open().
	DriverName string

	// ErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or no error code can be
	// determined, ErrorCode should return an empty string.
	ErrorCode func(error) string

	// If not nil, PreprocessDSN will be called on a dataSourceName right
	// before it is passed in to sql.Open().
	PreprocessDSN func(string) (string, error)
}

// Registers registers a driver for a particular database dialect.
func RegisterDriver(d Driver) {
	dbDriversMu.Lock()
	defer dbDriversMu.Unlock()
	if d.Dialect == "" {
		panic("notebrew: driver dialect cannot be empty")
	}
	if _, dup := dbDrivers[d.Dialect]; dup {
		panic("notebrew: RegisterDialect called twice for dialect " + d.Dialect)
	}
	dbDrivers[d.Dialect] = d
}

func (nb *Notebrew) TrimContentDomain(s string) string {
	if !strings.HasSuffix(s, nb.ContentDomain) {
		return s
	}
	trimmed := strings.TrimSuffix(s, nb.ContentDomain)
	if !strings.HasSuffix(trimmed, ".") {
		return s
	}
	return strings.TrimSuffix(trimmed, ".")
}

func (nb *Notebrew) IsKeyViolation(err error) bool {
	if err == nil || nb.ErrorCode == nil {
		return false
	}
	errcode := nb.ErrorCode(err)
	switch nb.Dialect {
	case "sqlite":
		return errcode == "1555" || errcode == "2067" // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
	case "postgres":
		return errcode == "23505" // unique_violation
	case "mysql":
		return errcode == "1062" // ER_DUP_ENTRY
	case "sqlserver":
		return errcode == "2627"
	default:
		return false
	}
}

func (nb *Notebrew) IsForeignKeyViolation(err error) bool {
	if err == nil || nb.ErrorCode == nil {
		return false
	}
	errcode := nb.ErrorCode(err)
	switch nb.Dialect {
	case "sqlite":
		return errcode == "787" //  SQLITE_CONSTRAINT_FOREIGNKEY
	case "postgres":
		return errcode == "23503" // foreign_key_violation
	case "mysql":
		return errcode == "1216" // ER_NO_REFERENCED_ROW
	case "sqlserver":
		return errcode == "547"
	default:
		return false
	}
}

func (nb *Notebrew) executeTemplate(sitename string, dest io.Writer, src any, content string) error {
	var text string
	switch src := src.(type) {
	case string:
		text = src
	case fs.File:
		var b strings.Builder
		fileinfo, err := src.Stat()
		if err != nil {
			return err
		}
		b.Grow(int(fileinfo.Size()))
		_, err = io.Copy(&b, src)
		if err != nil {
			return err
		}
		src.Close()
		text = b.String()
	default:
		return fmt.Errorf("unsupported src type (must be string or fs.File)")
	}
	funcmap := map[string]any{
		"content": func() template.HTML { return template.HTML(content) },
	}
	main, err := template.New("").Funcs(funcmap).Parse(text)
	if err != nil {
		return err
	}

	visited := make(map[string]struct{})
	page := template.New("").Funcs(funcmap)
	tmpls := main.Templates()
	sort.SliceStable(tmpls, func(i, j int) bool {
		return tmpls[i].Name() < tmpls[j].Name()
	})
	var tmpl *template.Template
	var nodes []parse.Node
	var node parse.Node
	var errmsgs []string
	for len(tmpls) > 0 {
		tmpl, tmpls = tmpls[len(tmpls)-1], tmpls[:len(tmpls)-1]
		if tmpl.Tree == nil {
			continue
		}
		if cap(nodes) < len(tmpl.Tree.Root.Nodes) {
			nodes = make([]parse.Node, 0, len(tmpl.Tree.Root.Nodes))
		}
		for i := len(tmpl.Tree.Root.Nodes) - 1; i >= 0; i-- {
			nodes = append(nodes, tmpl.Tree.Root.Nodes[i])
		}
		for len(nodes) > 0 {
			node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
			switch node := node.(type) {
			case *parse.ListNode:
				for i := len(node.Nodes) - 1; i >= 0; i-- {
					nodes = append(nodes, node.Nodes[i])
				}
			case *parse.BranchNode:
				nodes = append(nodes, node.List)
				if node.ElseList != nil {
					nodes = append(nodes, node.ElseList)
				}
			case *parse.RangeNode:
				nodes = append(nodes, node.List)
				if node.ElseList != nil {
					nodes = append(nodes, node.ElseList)
				}
			case *parse.TemplateNode:
				if !strings.HasSuffix(node.Name, ".html") {
					continue
				}
				if _, ok := visited[node.Name]; ok {
					continue
				}
				visited[node.Name] = struct{}{}
				name := path.Join("templates", node.Name)
				if sitename != "" {
					name = path.Join("~"+sitename, name)
				}
				file, err := nb.FS.Open(name)
				if errors.Is(err, fs.ErrNotExist) {
					errmsgs = append(errmsgs, fmt.Sprintf("%s: %s does not exist", tmpl.Name(), node.String()))
					continue
				}
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				fileinfo, err := file.Stat()
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				var b strings.Builder
				b.Grow(int(fileinfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				file.Close()
				text := b.String()
				t, err := template.New(node.Name).Funcs(funcmap).Parse(text)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				parsedTemplates := t.Templates()
				sort.SliceStable(parsedTemplates, func(i, j int) bool {
					return parsedTemplates[i].Name() < parsedTemplates[j].Name()
				})
				for _, t := range parsedTemplates {
					_, err = page.AddParseTree(t.Name(), t.Tree)
					if err != nil {
						return fmt.Errorf("%s: adding %s: %w", node.Name, t.Name(), err)
					}
					tmpls = append(tmpls, t)
				}
			}
		}
	}
	if len(errmsgs) > 0 {
		return fmt.Errorf("invalid template references:\n" + strings.Join(errmsgs, "\n"))
	}

	for _, t := range main.Templates() {
		_, err = page.AddParseTree(t.Name(), t.Tree)
		if err != nil {
			return fmt.Errorf("adding %s: %w", t.Name(), err)
		}
	}
	err = page.ExecuteTemplate(dest, "", nil)
	if err != nil {
		return err
	}
	return nil
}

func callermsg(a ...any) string {
	_, file, line, _ := runtime.Caller(1)
	var b strings.Builder
	b.WriteString(file + ":" + strconv.Itoa(line))
	for _, v := range a {
		b.WriteString("\n" + fmt.Sprint(v))
	}
	return b.String()
}

func serveFile(w http.ResponseWriter, r *http.Request, file fs.File) {
	fileinfo, err := file.Stat()
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	if fileinfo.IsDir() {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	name := fileinfo.Name()
	if strings.HasSuffix(name, ".gz") {
		name = strings.TrimSuffix(name, ".gz")
		w.Header().Set("Content-Encoding", "gzip")
	}
	fileseeker, ok := file.(io.ReadSeeker)
	if ok {
		http.ServeContent(w, r, name, fileinfo.ModTime(), fileseeker)
		return
	}
	var buf bytes.Buffer
	buf.Grow(int(fileinfo.Size()))
	_, err = buf.ReadFrom(file)
	if err != nil {
		http.Error(w, callermsg(err), http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, name, fileinfo.ModTime(), bytes.NewReader(buf.Bytes()))
}

func (nb *Notebrew) serveUserFile(w http.ResponseWriter, r *http.Request, sitename string, urlpath string) {
	if !strings.HasPrefix(urlpath, "static/") && !strings.HasPrefix(urlpath, "images/") {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	name := urlpath
	if sitename != "" {
		if strings.Contains(sitename, ".") {
			name = path.Join(sitename, urlpath)
		} else {
			name = path.Join("~"+sitename, urlpath)
		}
	}
	file, err := nb.FS.Open(name)
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

func (nb *Notebrew) sessionTokenHash(r *http.Request) []byte {
	cookie, _ := r.Cookie("session")
	if cookie == nil {
		return nil
	}
	if cookie.Value == "" {
		return nil
	}
	sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
	if err != nil {
		return nil
	}
	checksum := sha256.Sum256([]byte(sessionToken[8:]))
	var sessionTokenHash [8 + sha256.Size]byte
	copy(sessionTokenHash[:8], sessionToken[:8])
	copy(sessionTokenHash[8:], checksum[:])
	return sessionTokenHash[:]
}

func (nb *Notebrew) AdminOrigin() string {
	if nb.AdminDomain != "" {
		return "https://" + nb.AdminDomain
	}
	return "http://localhost:" + strconv.Itoa(nb.Port)
}

func (nb *Notebrew) ContentOrigin() string {
	if nb.ContentDomain != "" {
		return "https://" + nb.ContentDomain
	}
	return "http://localhost:" + strconv.Itoa(nb.Port)
}

type dirFS string

func DirFS(dir string) fs.FS {
	return dirFS(dir)
}

func (dir dirFS) Open(name string) (fs.File, error) {
	return os.Open(filepath.ToSlash(filepath.Join(string(dir), name)))
}

func (dir dirFS) OpenWriter(name string) (io.WriteCloser, error) {
	var err error
	f := tmpfile{
		dir:  os.TempDir(),
		dest: filepath.Join(string(dir), name),
	}
	f.file, err = os.CreateTemp(f.dir, "notebrew_temp/*")
	if err != nil {
		return nil, err
	}
	return f, nil
}

type tmpfile struct {
	dir  string
	file *os.File
	dest string
}

func (f tmpfile) Write(p []byte) (n int, err error) {
	return f.file.Write(p)
}

func (f tmpfile) Close() error {
	fileinfo, err := f.file.Stat()
	if err != nil {
		return err
	}
	err = f.file.Close()
	if err != nil {
		return err
	}
	src := filepath.Join(f.dir, fileinfo.Name())
	return os.Rename(filepath.ToSlash(src), filepath.ToSlash(f.dest))
}

func (dir dirFS) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(filepath.ToSlash(path), perm)
}

func (dir dirFS) RemoveAll(path string) error {
	return os.RemoveAll(filepath.ToSlash(filepath.Join(string(dir), path)))
}

func (dir dirFS) WalkDir(root string, fn fs.WalkDirFunc) error {
	return filepath.WalkDir(filepath.Join(string(dir), root), func(name string, d fs.DirEntry, err error) error {
		name = strings.TrimPrefix(name, string(dir))
		name = strings.TrimPrefix(name, string(os.PathSeparator))
		return fn(filepath.ToSlash(name), d, err)
	})
}
