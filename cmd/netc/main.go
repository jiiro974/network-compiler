package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"network-compiler/internal/compliance"
	"network-compiler/internal/diff"
	"network-compiler/internal/ir"
	"network-compiler/internal/parser"
	"network-compiler/internal/parser/cisco"
	"network-compiler/internal/parser/juniper"
	"network-compiler/internal/query"
	"network-compiler/internal/report"
	"network-compiler/internal/server"
	"network-compiler/internal/store"
)

func init() {
	parser.Register("cisco", cisco.New())
	parser.Register("juniper", juniper.New())
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "check":
		return checkCmd(args[1:])
	case "diff":
		return diffCmd(args[1:])
	case "ingest":
		return ingestCmd(args[1:])
	case "inventory":
		return inventoryCmd(args[1:])
	case "parse":
		return parseCmd(args[1:])
	case "query":
		return queryCmd(args[1:])
	case "serve":
		return serveCmd(args[1:])
	case "help", "-h", "--help":
		return usage()
	default:
		return fmt.Errorf("commande inconnue: %s", args[0])
	}
}

func parseCmd(args []string) error {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	vendor := fs.String("vendor", "cisco", "vendor parser: cisco, juniper, auto")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: netc parse [--vendor cisco] <config>")
	}
	p, _, err := parser.Select(*vendor, fs.Arg(0))
	if err != nil {
		return err
	}
	dev, err := p.ParseFile(fs.Arg(0))
	if err != nil {
		return err
	}
	return printJSON(dev)
}

func ingestCmd(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	input := fs.String("input", "", "config file, glob, or directory")
	vendor := fs.String("vendor", "cisco", "vendor parser: cisco, juniper, auto")
	out := fs.String("out", "netc-inventory.jsonl", "JSONL inventory output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("usage: netc ingest --input <config|glob|dir> [--vendor cisco|juniper|auto] [--out netc-inventory.jsonl]")
	}
	inputs, err := expandInput(*input)
	if err != nil {
		return err
	}
	devices, err := parseFiles(*vendor, inputs)
	if err != nil {
		return err
	}
	if err := store.WriteJSONL(*out, devices); err != nil {
		return err
	}
	s := report.Summarize(devices)
	fmt.Fprintf(os.Stderr, "wrote %s devices=%d interfaces=%d vlans=%d routes=%d acls=%d\n", *out, s.Devices, s.Interfaces, s.VLANs, s.Routes, s.ACLs)
	return nil
}

func inventoryCmd(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	input := fs.String("input", "", "config file, glob, directory, or JSONL inventory")
	vendor := fs.String("vendor", "cisco", "vendor parser for config input: cisco, juniper, auto")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("usage: netc inventory --input <config|glob|dir|inventory.jsonl> [--json]")
	}
	devices, err := loadDevices(*vendor, *input)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(report.Summarize(devices))
	}
	return report.WriteInventory(os.Stdout, devices)
}

func diffCmd(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	vendor := fs.String("vendor", "cisco", "vendor parser for config input: cisco, juniper, auto")
	beforePath := fs.String("before", "", "before config")
	afterPath := fs.String("after", "", "after config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *beforePath == "" || *afterPath == "" {
		return fmt.Errorf("usage: netc diff --before <config> --after <config>")
	}
	beforeParser, _, err := parser.Select(*vendor, *beforePath)
	if err != nil {
		return err
	}
	before, err := beforeParser.ParseFile(*beforePath)
	if err != nil {
		return err
	}
	afterParser, _, err := parser.Select(*vendor, *afterPath)
	if err != nil {
		return err
	}
	after, err := afterParser.ParseFile(*afterPath)
	if err != nil {
		return err
	}
	changes := diff.Devices(before, after)
	if len(changes) == 0 {
		fmt.Println("aucun changement")
		return nil
	}
	return printJSON(changes)
}

func checkCmd(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	input := fs.String("input", "", "config file, glob, directory, or JSONL inventory")
	vendor := fs.String("vendor", "cisco", "vendor parser for config input: cisco, juniper, auto")
	policyPath := fs.String("policy", "", "JSON policy file")
	ntp := fs.String("ntp", "", "comma-separated required NTP servers")
	syslog := fs.String("syslog", "", "comma-separated required syslog hosts")
	forbidSNMP := fs.String("forbid-snmp-community", "", "comma-separated forbidden SNMP communities")
	limit := fs.Int("limit", 0, "maximum number of findings to print")
	summary := fs.Bool("summary", false, "print summary only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("usage: netc check --input <config|glob|dir|inventory.jsonl> [--ntp a,b] [--syslog a,b] [--forbid-snmp-community public]")
	}
	devices, err := loadDevices(*vendor, *input)
	if err != nil {
		return err
	}
	policy, err := policyFromFlags(*policyPath, *ntp, *syslog, *forbidSNMP)
	if err != nil {
		return err
	}
	findings := compliance.Check(devices, policy)
	if len(findings) == 0 {
		fmt.Println("conforme")
		return nil
	}
	if *summary {
		return printJSON(compliance.Summarize(findings))
	}
	if *limit > 0 && len(findings) > *limit {
		findings = findings[:*limit]
	}
	return printJSON(findings)
}

func queryCmd(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	input := fs.String("input", "", "config input file")
	vendor := fs.String("vendor", "cisco", "vendor parser for config input: cisco, juniper, auto")
	limit := fs.Int("limit", 0, "maximum number of results to print")
	brief := fs.Bool("brief", false, "print compact results without full IR objects")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" || fs.NArg() < 1 {
		return fmt.Errorf("usage: netc query --input <config|glob|dir> [more-configs...] <query>")
	}
	inputs, queryText, err := queryInputs(*input, fs.Args())
	if err != nil {
		return err
	}
	devices, err := loadDevicesFromInputs(*vendor, inputs)
	if err != nil {
		return err
	}
	results, err := query.Run(devices, queryText)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Println("non trouvé")
		return nil
	}
	if *limit > 0 && len(results) > *limit {
		results = results[:*limit]
	}
	if *brief {
		return printJSON(briefResults(results))
	}
	return printJSON(results)
}

func serveCmd(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	input := fs.String("input", "", "config file, glob, directory, or JSONL inventory")
	vendor := fs.String("vendor", "cisco", "vendor parser for config input: cisco, juniper, auto")
	policyPath := fs.String("policy", "", "JSON policy file")
	addr := fs.String("addr", "127.0.0.1:8787", "HTTP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("usage: netc serve --input <config|glob|dir|inventory.jsonl> [--addr 127.0.0.1:8787]")
	}
	devices, err := loadDevices(*vendor, *input)
	if err != nil {
		return err
	}
	policy, err := policyFromFlags(*policyPath, "", "", "")
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "serving %d devices at http://%s\n", len(devices), *addr)
	return http.ListenAndServe(*addr, server.New(devices, policy).Handler())
}

func queryInputs(first string, args []string) ([]string, string, error) {
	inputs, err := expandInput(first)
	if err != nil {
		return nil, "", err
	}

	queryStart := 0
	for queryStart < len(args) {
		more, err := expandInput(args[queryStart])
		if err != nil {
			return nil, "", err
		}
		if len(more) == 0 {
			break
		}
		inputs = append(inputs, more...)
		queryStart++
	}
	if queryStart >= len(args) {
		return nil, "", fmt.Errorf("requete manquante")
	}
	return inputs, strings.Join(args[queryStart:], " "), nil
}

func expandInput(path string) ([]string, error) {
	matches, err := filepath.Glob(path)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		matches = []string{path}
	}

	var files []string
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		if info.IsDir() {
			err := filepath.WalkDir(match, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		files = append(files, match)
	}
	return files, nil
}

func parseFiles(vendor string, inputs []string) ([]ir.Device, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("aucun fichier input trouve")
	}
	devices := make([]ir.Device, 0, len(inputs))
	for _, input := range inputs {
		p, _, err := parser.Select(vendor, input)
		if err != nil {
			return nil, err
		}
		dev, err := p.ParseFile(input)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", input, err)
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

type briefResult struct {
	Type     string      `json:"type"`
	Device   string      `json:"device"`
	Summary  string      `json:"summary"`
	Evidence ir.Evidence `json:"evidence"`
}

func briefResults(results []query.Result) []briefResult {
	out := make([]briefResult, 0, len(results))
	for _, result := range results {
		out = append(out, briefResult{
			Type:     result.Type,
			Device:   result.Device,
			Summary:  result.Summary,
			Evidence: result.Evidence,
		})
	}
	return out
}

func loadDevices(vendor, input string) ([]ir.Device, error) {
	inputs, err := expandInput(input)
	if err != nil {
		return nil, err
	}
	return loadDevicesFromInputs(vendor, inputs)
}

func loadDevicesFromInputs(vendor string, inputs []string) ([]ir.Device, error) {
	if len(inputs) == 1 && strings.HasSuffix(inputs[0], ".jsonl") {
		return store.ReadJSONL(inputs[0])
	}
	return parseFiles(vendor, inputs)
}

func splitCSV(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func policyFromFlags(path, ntp, syslog, forbidSNMP string) (compliance.Policy, error) {
	var policy compliance.Policy
	if path != "" {
		loaded, err := compliance.ReadPolicy(path)
		if err != nil {
			return compliance.Policy{}, err
		}
		policy = loaded
	}
	if values := splitCSV(ntp); len(values) > 0 {
		policy.RequiredNTPServers = values
	}
	if values := splitCSV(syslog); len(values) > 0 {
		policy.RequiredSyslogHosts = values
	}
	if values := splitCSV(forbidSNMP); len(values) > 0 {
		policy.ForbiddenSNMPCommunities = values
	}
	return policy, nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func usage() error {
	fmt.Println("usage: netc <check|diff|ingest|inventory|parse|query|serve>")
	return nil
}
