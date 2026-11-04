// Command mmft is the Meerkat MFT CLI. Every command runs without prompts and
// writes JSON to stdout, and failures write JSON to stderr, so it can run from a
// script. The exception is version, which prints plain text.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"mmft.dev/mmft/internal/statement"
	"mmft.dev/mmft/internal/trust"
	"mmft.dev/mmft/internal/version"
)

// Exit codes. Scripts can treat exitExists as a safe repeat run.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitExists  = 3
	// exitRefused means an agent did not match what was collected from its host.
	exitRefused = 4
)

const usage = `usage:
  mmft version
  mmft trust init --dir DIR --passphrase-file FILE
  mmft trust fingerprint --public FILE
  mmft trust certify-admin --root-dir DIR --root-fingerprint HEX --passphrase-file FILE
                           --request FILE --admin-fingerprint HEX --out FILE [--days N]
  mmft trust verify-admin --root-public FILE --root-fingerprint HEX --certificate FILE
  mmft admin init --dir DIR --owner NAME --passphrase-file FILE
  mmft agent token --api HOST:PORT --ca-fingerprint HEX --token-file FILE --workspace NAME
                   --name NAME --orchestrator HOST:PORT --root-fingerprint HEX
  mmft agent approve --api HOST:PORT --ca-fingerprint HEX --token-file FILE
                     --admin-dir DIR --passphrase-file FILE --certificate FILE
                     --root-public FILE --root-fingerprint HEX --fingerprints FILE [--days N]
`

var errUsage = errors.New("incorrect usage")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

func run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	err := dispatch(args, stdout, stderr, now)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errUsage):
		_, _ = io.WriteString(stderr, usage)
		return exitUsage
	case errors.Is(err, errRefused):
		_ = output(stderr, map[string]string{"error": err.Error()})
		return exitRefused
	case errors.Is(err, os.ErrExist):
		_ = output(stderr, map[string]string{"error": "already exists"})
		return exitExists
	default:
		_ = output(stderr, map[string]string{"error": err.Error()})
		return exitFailure
	}
}

func dispatch(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return errUsage
	}
	if args[0] == "version" {
		_, err := fmt.Fprintln(stdout, version.String("mmft"))
		return err
	}
	if len(args) < 2 {
		return errUsage
	}
	rest := args[2:]
	switch args[0] + " " + args[1] {
	case "trust init":
		return trustInit(rest, stdout, stderr)
	case "trust fingerprint":
		return trustFingerprint(rest, stdout, stderr)
	case "trust certify-admin":
		return certifyAdmin(rest, stdout, stderr, now)
	case "trust verify-admin":
		return verifyAdmin(rest, stdout, stderr, now)
	case "admin init":
		return adminInit(rest, stdout, stderr)
	case "agent token":
		return agentToken(rest, stdout, stderr, now)
	case "agent approve":
		return agentApprove(rest, stdout, stderr, now)
	default:
		return errUsage
	}
}

// parse reads flags and rejects missing required ones and stray arguments.
func parse(fs *flag.FlagSet, args []string, stderr io.Writer, required ...string) error {
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	for _, name := range required {
		if fs.Lookup(name).Value.String() == "" {
			return errUsage
		}
	}
	return nil
}

func output(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func trustInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("trust init", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory for the new trust root")
	passFile := fs.String("passphrase-file", "", "file holding the passphrase")
	if err := parse(fs, args, stderr, "dir", "passphrase-file"); err != nil {
		return err
	}
	passphrase, err := trust.ReadPassphrase(*passFile)
	if err != nil {
		return err
	}
	pub, err := trust.InitRoot(*dir, passphrase)
	if err != nil {
		return err
	}
	return output(stdout, map[string]string{"fingerprint": pub.Fingerprint()})
}

func trustFingerprint(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("trust fingerprint", flag.ContinueOnError)
	public := fs.String("public", "", "public key file")
	if err := parse(fs, args, stderr, "public"); err != nil {
		return err
	}
	record, err := trust.ReadPublic(*public)
	if err != nil {
		return err
	}
	key, err := record.Key()
	if err != nil {
		return err
	}
	return output(stdout, map[string]string{"owner": record.Owner, "fingerprint": key.Fingerprint()})
}

func adminInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("admin init", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory for the new key")
	owner := fs.String("owner", "", "name of the administrator")
	passFile := fs.String("passphrase-file", "", "file holding the passphrase")
	if err := parse(fs, args, stderr, "dir", "owner", "passphrase-file"); err != nil {
		return err
	}
	passphrase, err := trust.ReadPassphrase(*passFile)
	if err != nil {
		return err
	}
	pub, err := trust.InitAdministrator(*dir, *owner, passphrase)
	if err != nil {
		return err
	}
	return output(stdout, map[string]string{"owner": *owner, "fingerprint": pub.Fingerprint()})
}

func certifyAdmin(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("trust certify-admin", flag.ContinueOnError)
	rootDir := fs.String("root-dir", "", "directory holding the trust root")
	rootPin := fs.String("root-fingerprint", "", "pinned trust root fingerprint")
	passFile := fs.String("passphrase-file", "", "file holding the root passphrase")
	request := fs.String("request", "", "administrator's public key file")
	adminPin := fs.String("admin-fingerprint", "", "fingerprint confirmed with the administrator")
	out := fs.String("out", "", "file for the new certificate")
	days := fs.Int("days", 365, "certificate lifetime in days, up to 365")
	if err := parse(fs, args, stderr, "root-dir", "root-fingerprint", "passphrase-file", "request", "admin-fingerprint", "out"); err != nil {
		return err
	}
	if *days < 1 || *days > 365 {
		return errUsage
	}
	passphrase, err := trust.ReadPassphrase(*passFile)
	if err != nil {
		return err
	}
	root, _, err := trust.LoadKey(filepath.Join(*rootDir, trust.RootKeyFile), passphrase, statement.RoleRoot)
	if err != nil {
		return err
	}
	admin, err := trust.ReadPublic(*request)
	if err != nil {
		return err
	}
	e, err := trust.CertifyAdministrator(root, *rootPin, admin, *adminPin, now(), time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	if err := trust.WriteCertificate(*out, e); err != nil {
		return err
	}
	return output(stdout, map[string]string{"owner": admin.Owner, "fingerprint": *adminPin})
}

func verifyAdmin(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("trust verify-admin", flag.ContinueOnError)
	rootPublic := fs.String("root-public", "", "trust root's public key file")
	pinned := fs.String("root-fingerprint", "", "expected trust root fingerprint")
	certificate := fs.String("certificate", "", "administrator's certificate")
	if err := parse(fs, args, stderr, "root-public", "root-fingerprint", "certificate"); err != nil {
		return err
	}
	record, err := trust.ReadPublic(*rootPublic)
	if err != nil {
		return err
	}
	root, err := record.Key()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Clean(*certificate))
	if err != nil {
		return err
	}
	v, claim, err := trust.VerifyAdministrator(data, root, *pinned, now())
	if err != nil {
		return err
	}
	return output(stdout, map[string]string{
		"owner":       claim.Owner,
		"fingerprint": v.Key.Fingerprint(),
		"not_after":   claim.NotAfter.Format(time.RFC3339),
	})
}
