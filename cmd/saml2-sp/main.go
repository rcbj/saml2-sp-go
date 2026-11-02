// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rcbj/saml2-sp-go"
)

const usageText = `Usage:
  saml2-sp generate-keys --config <saml.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  saml2-sp generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The common name defaults to the host of the configuration's entityId.

  saml2-sp metadata --config <saml.json> [--out <file>] [--entity-id <url>] [--acs-url <url>]
      This service provider's SAML metadata, from the configuration and its certificate. Written to
      --out, or to standard output. --entity-id and --acs-url replace the file's values for this run.

  saml2-sp summarize-idp
      Read identity-provider metadata on standard input. Write its entityID, its SSO URL, and one
      artifact-resolution URL per line.`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(argv []string) error {
	command, args, err := parseArgs(argv)
	if err != nil {
		return err
	}
	if command == "" || args["help"] == "true" || command == "help" {
		fmt.Println(usageText)
		return nil
	}
	switch command {
	case "generate-keys":
		return generateKeys(args)
	case "metadata":
		return writeMetadata(args)
	case "summarize-idp":
		return summarize(os.Stdin)
	default:
		return fmt.Errorf("unknown command %s\n\n%s", command, usageText)
	}
}

func parseArgs(argv []string) (string, map[string]string, error) {
	command := ""
	rest := argv
	if len(argv) > 0 {
		command = argv[0]
		rest = argv[1:]
	}
	args := map[string]string{}
	for index := 0; index < len(rest); index++ {
		item := rest[index]
		if !strings.HasPrefix(item, "--") {
			return "", nil, fmt.Errorf("unexpected argument %s\n\n%s", item, usageText)
		}
		key := item[2:]
		if key == "force" || key == "help" {
			args[key] = "true"
			continue
		}
		if index+1 >= len(rest) || strings.HasPrefix(rest[index+1], "--") {
			return "", nil, fmt.Errorf("--%s needs a value\n\n%s", key, usageText)
		}
		index++
		args[key] = rest[index]
	}
	return command, args, nil
}

func generateKeys(args map[string]string) error {
	paths, err := keyPaths(args)
	if err != nil {
		return err
	}
	if args["force"] != "true" && (exists(paths.key) || exists(paths.cert)) {
		which := paths.cert
		if exists(paths.key) {
			which = paths.key
		}
		return fmt.Errorf("%s already exists; pass --force to replace the key pair.\nReplacing it means giving the identity provider the new metadata before the next sign-in.", which)
	}
	days := 1095
	if raw := args["days"]; raw != "" {
		days, err = strconv.Atoi(raw)
		if err != nil || days <= 0 {
			return fmt.Errorf("--days must be a positive whole number")
		}
	}
	bits := 3072
	if raw := args["bits"]; raw != "" {
		bits, err = strconv.Atoi(raw)
		if err != nil || (bits != 2048 && bits != 3072 && bits != 4096) {
			return fmt.Errorf("--bits must be 2048, 3072 or 4096")
		}
	}
	pair, err := saml.CreateSelfSignedKeyPair(paths.cn, days, bits)
	if err != nil {
		return err
	}
	if err := writeMode(paths.key, pair.PrivateKeyPEM, 0o600); err != nil {
		return err
	}
	if err := writeMode(paths.cert, pair.CertificatePEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("Wrote the private key  %s (mode 600)\n", paths.key)
	fmt.Printf("Wrote the certificate  %s\n", paths.cert)
	fmt.Printf("  subject   CN=%s\n", paths.cn)
	fmt.Printf("  valid to  %s\n", pair.ValidTo())
	fmt.Printf("  sha256    %s\n", pair.Fingerprint256())
	return nil
}

type keyLocations struct{ key, cert, cn string }

func keyPaths(args map[string]string) (keyLocations, error) {
	configPath := args["config"]
	key, cert, cn := args["key"], args["cert"], args["cn"]
	if configPath != "" {
		raw, err := readObject(configPath)
		if err != nil {
			return keyLocations{}, err
		}
		base := filepath.Dir(abs(configPath))
		at := func(value, what string) (string, error) {
			text, _ := valueString(raw[what])
			if text == "" || strings.Contains(text, "-----BEGIN ") {
				return "", fmt.Errorf("%s's %s must be a file path for generate-keys to write to", configPath, what)
			}
			if strings.HasPrefix(text, "file:") {
				text = text[5:]
			}
			if strings.HasPrefix(text, "env:") {
				return "", fmt.Errorf("%s's %s must be a file path for generate-keys to write to", configPath, what)
			}
			if !filepath.IsAbs(text) {
				text = filepath.Join(base, text)
			}
			return filepath.Clean(text), nil
		}
		if key == "" {
			key, err = at(rawString(raw, "privateKey"), "privateKey")
			if err != nil {
				return keyLocations{}, err
			}
		}
		if cert == "" {
			cert, err = at(rawString(raw, "certificate"), "certificate")
			if err != nil {
				return keyLocations{}, err
			}
		}
		if cn == "" {
			if entity := rawString(raw, "entityId"); entity != "" {
				if parsed, err := url.Parse(entity); err == nil && parsed.Hostname() != "" {
					cn = parsed.Hostname()
				} else {
					cn = entity
				}
			}
		}
	}
	if key == "" || cert == "" {
		return keyLocations{}, fmt.Errorf("generate-keys needs --config, or --key and --cert\n\n%s", usageText)
	}
	if cn == "" {
		cn = "saml2-sp service provider"
	}
	return keyLocations{key: abs(key), cert: abs(cert), cn: cn}, nil
}

func writeMetadata(args map[string]string) error {
	configPath := args["config"]
	if configPath == "" {
		return fmt.Errorf("metadata needs --config\n\n%s", usageText)
	}
	raw, err := readObject(configPath)
	if err != nil {
		return err
	}
	delete(raw, "idpCa")
	if args["entity-id"] != "" {
		raw["entityId"] = args["entity-id"]
	}
	if args["acs-url"] != "" {
		raw["acsUrl"] = args["acs-url"]
	}
	cfg, err := saml.ResolveConfig(raw, filepath.Dir(abs(configPath)))
	if err != nil {
		return err
	}
	xml := saml.MetadataDocument(cfg)
	if target := args["out"]; target != "" {
		if err := writeMode(abs(target), xml, 0o644); err != nil {
			return err
		}
		fmt.Printf("Wrote the service provider metadata to %s\n", abs(target))
		return nil
	}
	fmt.Print(xml)
	return nil
}

func summarize(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, 2<<20))
	if err != nil {
		return err
	}
	meta, err := saml.ReadIDPMetadata(string(raw))
	if err != nil {
		return err
	}
	fmt.Println(meta.EntityID)
	sso := meta.SSO["redirect"]
	if sso == "" {
		sso = meta.SSO["post"]
	}
	fmt.Println(sso)
	var indexes []int
	for index := range meta.ArtifactResolutionServices {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	for _, index := range indexes {
		fmt.Println(meta.ArtifactResolutionServices[index])
	}
	return nil
}

func readObject(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", path)
	}
	return obj, nil
}

func rawString(obj map[string]any, key string) string {
	text, _ := valueString(obj[key])
	return text
}

func valueString(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func abs(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	full, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return full
}

func writeMode(path, text string, mode os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
