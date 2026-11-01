// Command mmft-orchestrator runs the orchestrator. For now it can only prepare
// the database, using the URL in MMFT_DATABASE_URL.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"mmft.dev/mmft/internal/db"
	"mmft.dev/mmft/internal/version"
)

const migrateTimeout = 2 * time.Minute

func main() {
	os.Exit(run(os.Args[1:], os.Getenv("MMFT_DATABASE_URL"), os.Stdout, os.Stderr))
}

func run(args []string, url string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "migrate" {
		if err := migrate(url, stdout); err != nil {
			_ = json.NewEncoder(stderr).Encode(map[string]string{"error": err.Error()})
			return 1
		}
		return 0
	}
	if len(args) == 0 || (len(args) == 1 && args[0] == "version") {
		_, _ = fmt.Fprintln(stdout, version.String("mmft-orchestrator"))
		return 0
	}
	_, _ = io.WriteString(stderr, "usage: mmft-orchestrator [version | migrate]\n")
	return 2
}

func migrate(url string, stdout io.Writer) error {
	if url == "" {
		return errors.New("MMFT_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), migrateTimeout)
	defer cancel()
	pool, err := db.Open(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := db.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]int{"applied": applied})
}
