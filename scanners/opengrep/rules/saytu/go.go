package samples

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"
)

func tlsConfig() *tls.Config {
	// ruleid: saytu.go.tls-insecure-skip-verify
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
}

func tlsSafe() *tls.Config {
	// ok: saytu.go.tls-insecure-skip-verify
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func queries(ctx context.Context, db *sql.DB, name string, id int) {
	// ruleid: saytu.go.sql-injection
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	// ruleid: saytu.go.sql-injection
	db.ExecContext(ctx, "DELETE FROM t WHERE name = '"+name+"'")
	q := fmt.Sprintf("SELECT * FROM t WHERE id = %d", id)
	// ruleid: saytu.go.sql-injection
	db.QueryRow(q)
	// ok: saytu.go.sql-injection
	db.Query("SELECT * FROM users WHERE name = $1", name)
}

func commands(arg string) {
	// ruleid: saytu.go.command-injection
	exec.Command("sh", "-c", "ls "+arg).Run()
	// ok: saytu.go.command-injection
	exec.Command("ls", arg).Run()
	// ok: saytu.go.command-injection
	exec.Command("/bin/sh", "-c", "uptime").Run()
}

func hashes(data []byte) {
	// ruleid: saytu.go.weak-hash
	md5.Sum(data)
	// ruleid: saytu.go.weak-hash
	sha1.New()
	// ok: saytu.go.weak-hash
	sha256.Sum256(data)
}
