package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bokwoon95/nb3"
)

var open = func(address string) {}

// TODO: How to orchestrate the following? Requires access to the database. But
// there may be multiple databases, each one corresponding to a http.Server.
// $ notebrew hashpassword <password> (blank uses getpasswd, allows plaintext argument, alternatively can be piped in)
// $ notebrew create user -email <email> -name <name> -password <password> -password-hash <hash>
// $ notebrew update user -email <email> -name <name> -password <password> -password-hash <hash>
// func NewDB(fsys FS) (*sql.DB, error)

func main() {
	var dir, addr, db string
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.StringVar(&dir, "dir", "", "")
	flagset.StringVar(&addr, "addr", "", "")
	flagset.StringVar(&db, "db", "", "")
	err := flagset.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		exit(err)
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			exit(err)
		}
		dir = filepath.Join(userHomeDir, "notebrewdata")
	}
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		exit(err)
	}
	addr = strings.TrimSpace(addr)
	if addr != "" {
		file, err := os.OpenFile(filepath.Join(dir, "address.txt"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			exit(err)
		}
		_, err = file.WriteString(addr)
		if err != nil {
			exit(err)
		}
		err = file.Close()
		if err != nil {
			exit(err)
		}
	}
	db = strings.TrimSpace(db)
	if db != "" {
		file, err := os.OpenFile(filepath.Join(dir, "database.txt"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			exit(err)
		}
		_, err = file.WriteString(db)
		if err != nil {
			exit(err)
		}
		err = file.Close()
		if err != nil {
			exit(err)
		}
	}
	nb, err := nb3.New(nb3.DirFS(dir))
	if err != nil {
		exit(err)
	}
	defer nb.Close()
	args := flagset.Args()
	if len(args) > 0 {
		if nb.DB == nil {
			err = os.WriteFile(filepath.Join(dir, "database.txt"), []byte("sqlite"), 0644)
			if err != nil {
				exit(err)
			}
			nb, err = nb3.New(nb3.DirFS(dir))
			if err != nil {
				exit(err)
			}
		}
		command, args := args[0], args[1:]
		switch command {
		case "createsite":
			createSiteCmd, err := CreateSiteCommand(nb, args...)
			if err != nil {
				exit(fmt.Errorf(command+": %w", err))
			}
			err = createSiteCmd.Run()
			if err != nil {
				exit(fmt.Errorf(command+": %w", err))
			}
		case "createuser":
			createUserCmd, err := CreateUserCommand(nb, args...)
			if err != nil {
				exit(fmt.Errorf(command+": %w", err))
			}
			err = createUserCmd.Run()
			if err != nil {
				exit(fmt.Errorf(command+": %w", err))
			}
		case "resetpassword":
			resetPasswordCmd, err := ResetPasswordCommand(nb, args...)
			if err != nil {
				exit(fmt.Errorf(command+": %w", err))
			}
			err = resetPasswordCmd.Run()
			if err != nil {
				exit(fmt.Errorf(command+": %w", err))
			}
		case "hashpassword":
			hashPasswordCmd, err := HashPasswordCommand(args...)
			if err != nil {
				exit(fmt.Errorf(command+": %w", err))
			}
			err = hashPasswordCmd.Run()
			if err != nil {
				exit(fmt.Errorf(command+": %w", err))
			}
		default:
			exit(fmt.Errorf("unknown command %s", command))
		}
		return
	}
	server, err := nb.NewServer()
	if err != nil {
		exit(err)
	}
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-wait
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
	}()
	if server.Addr == ":443" || server.Addr == ":https" {
		go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" && r.Method != "HEAD" {
				http.Error(w, "Use HTTPS", http.StatusBadRequest)
				return
			}
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			} else {
				host = net.JoinHostPort(host, "443")
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
		}))
		fmt.Println("Listening on " + server.Addr)
		server.ListenAndServeTLS("", "")
		return
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			exit(err)
		}
		// WSAEADDRINUSE copied from
		// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
		// To avoid importing an entire 3rd party library just to use a constant.
		const WSAEADDRINUSE = syscall.Errno(10048)
		if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
			fmt.Println("http://" + server.Addr)
			open("http://" + server.Addr)
		}
		return
	}
	open("http://" + server.Addr)
	// NOTE: We may need to give a more intricate ASCII header in order for the
	// GUI double clickers to realize that the terminal window is important, so
	// that they won't accidentally close it thinking it is some random
	// terminal.
	fmt.Println("Listening on http://" + server.Addr)
	server.Serve(listener)
}
