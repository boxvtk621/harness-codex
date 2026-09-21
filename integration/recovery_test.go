package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/boxvtk621/harness-codex/runtime"
	_ "modernc.org/sqlite"
)

const spillChild = "HL252_SPILL_CHILD"

func TestSpilledRollbackJournalRecoversOwnedVolume(t *testing.T) {
	if path := os.Getenv(spillChild); path != "" {
		db, err := sql.Open("sqlite", "file:"+path+"?mode=rw&_pragma=journal_mode(DELETE)&_pragma=synchronous(EXTRA)&_pragma=foreign_keys(1)&_pragma=cache_size(8)")
		if err != nil {
			panic(err)
		}
		tx, err := db.Begin()
		if err != nil {
			panic(err)
		}
		if _, err := tx.Exec(`UPDATE policy_snapshots SET content=? WHERE effective_hash='spill'`, bytes.Repeat([]byte{0x5a}, 8<<20)); err != nil {
			panic(err)
		}
		journal := path + "-journal"
		deadline := time.Now().Add(3 * time.Second)
		for {
			if info, err := os.Stat(journal); err == nil && info.Size() > 1<<20 {
				break
			}
			if time.Now().After(deadline) {
				panic("journal did not spill")
			}
			time.Sleep(time.Millisecond)
		}
		fmt.Println("ready")
		for {
			time.Sleep(time.Hour)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	directory := t.TempDir()
	n, err := node.Open(ctx, config(directory))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(directory, "harness.db")
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Repeat([]byte{0x31}, 8<<20)
	if _, err := db.Exec(`INSERT INTO policy_snapshots(effective_hash,revision,content,content_hash,tool_manifest,tool_manifest_hash,approval_mode) VALUES('spill','r',?,'c',X'01','t','deny')`, original); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSpilledRollbackJournalRecoversOwnedVolume$", "-test.count=1")
	command.Env = append(os.Environ(), spillChild+"="+database)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("child readiness %q %v", line, err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	if info, err := os.Stat(database + "-journal"); err != nil || info.Size() <= 1<<20 {
		t.Fatalf("spilled journal missing: %v %+v", err, info)
	}
	reopened, err := node.Open(ctx, config(directory))
	if err != nil {
		t.Fatalf("owned hot journal recovery: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	check, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var content []byte
	if err := check.QueryRow(`SELECT content FROM policy_snapshots WHERE effective_hash='spill'`).Scan(&content); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, original) {
		t.Fatal("uncommitted spill survived rollback recovery")
	}
}
