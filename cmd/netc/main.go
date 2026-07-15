package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"network-compiler/internal/collect"
	"network-compiler/internal/compliance"
	"network-compiler/internal/creds"
	"network-compiler/internal/diag"
	"network-compiler/internal/diag/transport"
	"network-compiler/internal/diff"
	"network-compiler/internal/discovery"
	"network-compiler/internal/guard"
	"network-compiler/internal/ir"
	"network-compiler/internal/parser"
	"network-compiler/internal/parser/cisco"
	"network-compiler/internal/parser/fortios"
	"network-compiler/internal/parser/ioslike"
	"network-compiler/internal/parser/juniper"
	"network-compiler/internal/parser/routeros"
	"network-compiler/internal/parser/setform"
	"network-compiler/internal/parser/sros"
	"network-compiler/internal/parser/vlancentric"
	"network-compiler/internal/parser/vrp"
	pathtrace "network-compiler/internal/path"
	"network-compiler/internal/query"
	"network-compiler/internal/report"
	"network-compiler/internal/server"
	"network-compiler/internal/store"
	"network-compiler/internal/topology"
)

func init() {
	parser.Register("cisco", cisco.New())
	parser.Register("juniper", juniper.New())
	parser.Register("arista-eos", ioslike.New("arista-eos"))
	parser.Register("aruba-cx", ioslike.New("aruba-cx"))
	parser.Register("cisco-iosxr", ioslike.New("cisco-iosxr"))
	parser.Register("cisco-nxos", ioslike.New("cisco-nxos"))
	parser.Register("fs-fsos", ioslike.New("fs-fsos"))
	parser.Register("aruba-os-switch", vlancentric.NewArubaOSSwitch())
	parser.Register("hpe-procurve", vlancentric.NewHPEProCurve())
	parser.Register("extreme-exos", vlancentric.NewExtremeEXOS())
	parser.Register("huawei-vrp", vrp.NewHuaweiVRP())
	parser.Register("hpe-comware", vrp.NewHPEComware())
	parser.Register("vyos", setform.NewVendor("vyos"))
	parser.Register("ubiquiti-edgeos", setform.NewVendor("ubiquiti-edgeos"))
	parser.Register("paloalto-panos", setform.NewVendor("paloalto-panos"))
	parser.Register("mikrotik-routeros", routeros.New())
	parser.Register("fortinet-fortigate", fortios.New())
	parser.Register("nokia-sros", sros.New())
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
	case "collect":
		return collectCmd(args[1:])
	case "diag":
		return diagCmd(args[1:])
	case "discover":
		return discoverCmd(args[1:])
	case "diff":
		return diffCmd(args[1:])
	case "ingest":
		return ingestCmd(args[1:])
	case "inventory":
		return inventoryCmd(args[1:])
	case "parse":
		return parseCmd(args[1:])
	case "path":
		return pathCmd(args[1:])
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

func collectCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: netc collect <plan|run|verify|ingest>")
	}
	switch args[0] {
	case "plan":
		return collectPlanCmd(args[1:])
	case "run":
		return collectRunCmd(args[1:])
	case "verify":
		return collectVerifyCmd(args[1:])
	case "ingest":
		return collectIngestCmd(args[1:])
	default:
		return fmt.Errorf("commande collect inconnue: %s", args[0])
	}
}

func collectRunCmd(args []string) error {
	fs := flag.NewFlagSet("collect run", flag.ContinueOnError)
	planPath := fs.String("plan", "", "verified collect plan JSON")
	confirmHash := fs.String("confirm-plan-sha256", "", "expected plan sha256")
	out := fs.String("out", "", "output directory for collected show commands")
	simulate := fs.Bool("simulate", false, "simulate collection without network access")
	user := fs.String("user", "", "SSH username (overrides NETC_SSH_USER and credentials file)")
	passwordEnv := fs.String("password-env", "", "environment variable for SSH password (default NETC_SSH_PASSWORD)")
	keyFile := fs.String("key-file", "", "SSH private key file (overrides NETC_SSH_KEY_FILE)")
	credentialsFile := fs.String("credentials-file", "", "credentials YAML path (default NETC_CREDENTIALS or ~/.netc/credentials.yaml)")
	knownHosts := fs.String("known-hosts", "", "known_hosts file for SSH runner")
	insecureHostKey := fs.Bool("insecure-host-key", false, "skip SSH host key verification")
	execRunner := fs.Bool("exec-runner", false, "use shell-out ssh instead of native SSH")
	auditLog := fs.String("audit-log", "", "optional JSONL audit log path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planPath == "" || *confirmHash == "" || *out == "" {
		return fmt.Errorf("usage: netc collect run --plan <collect-plan.json> --confirm-plan-sha256 <hash> --out <dir> [--simulate] [--user admin] [--password-env NETC_SSH_PASSWORD] [--key-file path] [--known-hosts path]")
	}
	plan, err := guard.ReadPlan(*planPath)
	if err != nil {
		return err
	}
	if err := guard.VerifyPlanHash(plan, *confirmHash); err != nil {
		return err
	}
	var credRef diag.CredRef
	if !*simulate {
		resolved, err := creds.Resolve(creds.Options{
			User:            *user,
			PasswordEnv:     *passwordEnv,
			KeyFile:         *keyFile,
			CredentialsFile: *credentialsFile,
		})
		if err != nil {
			return err
		}
		credRef = resolved.CredRef()
		if strings.TrimSpace(credRef.Username) == "" {
			credRef.Username = "admin"
		}
	} else if strings.TrimSpace(*user) != "" {
		credRef.Username = *user
	}
	result, err := collect.Run(context.Background(), plan, collect.Options{
		OutDir:          *out,
		Simulate:        *simulate,
		User:            credRef.Username,
		Creds:           credRef,
		KnownHosts:      *knownHosts,
		InsecureHostKey: *insecureHostKey,
		UseExecRunner:   *execRunner,
		PlanVerified:    true,
		DefaultVendor:   "cisco-ios",
		AuditLog:        *auditLog,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "collected out=%s targets=%d commands=%d errors=%d simulate=%t\n",
		result.OutDir, len(result.Targets), result.Commands, result.Errors, *simulate)
	return nil
}

func collectIngestCmd(args []string) error {
	fs := flag.NewFlagSet("collect ingest", flag.ContinueOnError)
	input := fs.String("input", "", "collect output directory with per-device show-running-config.txt")
	out := fs.String("out", "inventory.jsonl", "JSONL inventory output")
	vendor := fs.String("vendor", "auto", "vendor parser: cisco, juniper, auto")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("usage: netc collect ingest --input <collect-out-dir> [--out inventory.jsonl] [--vendor auto]")
	}
	configs, err := collect.ConfigPaths(*input)
	if err != nil {
		return err
	}
	devices, err := parseFiles(*vendor, configs)
	if err != nil {
		return err
	}
	if err := store.WriteJSONL(*out, devices); err != nil {
		return err
	}
	s := report.Summarize(devices)
	fmt.Fprintf(os.Stderr, "ingested %s devices=%d interfaces=%d vlans=%d routes=%d acls=%d\n",
		*out, s.Devices, s.Interfaces, s.VLANs, s.Routes, s.ACLs)
	return nil
}

func collectPlanCmd(args []string) error {
	fs := flag.NewFlagSet("collect plan", flag.ContinueOnError)
	targetsPath := fs.String("targets", "", "explicit target inventory JSONL or JSON array")
	guardPath := fs.String("guard", "", "guard config JSON or simple YAML")
	out := fs.String("out", "collect-plan.json", "collect plan JSON output")
	summary := fs.Bool("summary", false, "print compact summary to stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetsPath == "" {
		return fmt.Errorf("usage: netc collect plan --targets <targets.jsonl> [--guard guard.yaml] [--out collect-plan.json] [--summary]")
	}
	cfg, err := guard.ReadConfig(*guardPath)
	if err != nil {
		return err
	}
	targets, err := guard.ReadTargets(*targetsPath)
	if err != nil {
		return err
	}
	plan, err := guard.BuildPlan(cfg, targets)
	if err != nil {
		return err
	}
	if cfg.Audit.LogFile != "" {
		if err := guard.WriteAudit(cfg.Audit.LogFile, plan, cfg); err != nil {
			return err
		}
	}
	if err := writeIndentedJSON(*out, plan); err != nil {
		return err
	}
	if *summary {
		fmt.Fprintf(os.Stdout, "targets=%d allowed=%d rejected=%d commands_allowed=%d commands_rejected=%d sha256=%s\n", plan.Summary.TargetsInput, plan.Summary.Allowed, plan.Summary.Rejected, plan.Summary.CommandsAllowed, plan.Summary.CommandsRejected, plan.SHA256)
	}
	fmt.Fprintf(os.Stderr, "wrote %s targets=%d allowed=%d rejected=%d sha256=%s\n", *out, plan.Summary.TargetsInput, plan.Summary.Allowed, plan.Summary.Rejected, plan.SHA256)
	return nil
}

func collectVerifyCmd(args []string) error {
	fs := flag.NewFlagSet("collect verify", flag.ContinueOnError)
	planPath := fs.String("plan", "", "collect plan JSON")
	confirmHash := fs.String("confirm-plan-sha256", "", "expected plan sha256")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planPath == "" || *confirmHash == "" {
		return fmt.Errorf("usage: netc collect verify --plan <collect-plan.json> --confirm-plan-sha256 <hash>")
	}
	plan, err := guard.ReadPlan(*planPath)
	if err != nil {
		return err
	}
	if err := guard.VerifyPlanHash(plan, *confirmHash); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "verified plan %s allowed=%d rejected=%d\n", *confirmHash, plan.Summary.Allowed, plan.Summary.Rejected)
	return nil
}

func discoverCmd(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	input := fs.String("input", "", "raw discovery directory")
	out := fs.String("out", "discovery.jsonl", "JSONL discovery facts output")
	summary := fs.Bool("summary", false, "print readable summary instead of writing JSONL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("usage: netc discover --input <raw-discovery-dir> [--out discovery.jsonl] [--summary]")
	}
	discovered, err := discovery.ParseDir(*input)
	if err != nil {
		return err
	}
	topo := topology.Build(discovered.Neighbors, discovered.Addresses)
	if *summary {
		writeDiscoverySummary(os.Stdout, discovered, topo)
		return nil
	}
	facts := discovery.Facts(discovered)
	facts = append(facts, topology.Facts(topo)...)
	if err := store.WriteRecordsJSONL(*out, facts); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s devices=%d neighbors=%d candidate_links=%d conflicts=%d\n", *out, len(discovered.Devices), len(discovered.Neighbors), len(topo.Links), len(topo.Conflicts))
	return nil
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
	helpQueries := fs.Bool("help-queries", false, "print supported query patterns")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *helpQueries {
		for _, pattern := range query.HelpPatterns() {
			fmt.Println(pattern)
		}
		return nil
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

func pathCmd(args []string) error {
	if len(args) > 0 && args[0] == "validate" {
		return pathValidateCmd(args[1:])
	}
	fs := flag.NewFlagSet("path", flag.ContinueOnError)
	storePath := fs.String("store", "", "JSONL inventory store")
	src := fs.String("src", "", "source IP address")
	dst := fs.String("dst", "", "destination IP address")
	proto := fs.String("proto", "tcp", "protocol")
	dport := fs.Int("dport", 0, "destination port")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *storePath == "" || *src == "" || *dst == "" || *proto == "" {
		return fmt.Errorf("usage: netc path --store store.jsonl --src <ip> --dst <ip> --proto <proto> --dport <port> [--json]")
	}
	devices, err := store.ReadJSONL(*storePath)
	if err != nil {
		return err
	}
	result, err := pathtrace.Trace(devices, pathtrace.Flow{Src: *src, Dst: *dst, Proto: *proto, DPort: *dport})
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(result)
	}
	writePathText(os.Stdout, result)
	return nil
}

func pathValidateCmd(args []string) error {
	fs := flag.NewFlagSet("path validate", flag.ContinueOnError)
	storePath := fs.String("store", "", "JSONL inventory store")
	src := fs.String("src", "", "source IP address")
	dst := fs.String("dst", "", "destination IP address")
	proto := fs.String("proto", "tcp", "protocol")
	dport := fs.Int("dport", 0, "destination port")
	runnerName := fs.String("runner", "ssh", "runner: ssh or exec")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *storePath == "" || *src == "" || *dst == "" || *proto == "" {
		return fmt.Errorf("usage: netc path validate --store store.jsonl --src <ip> --dst <ip> --proto <proto> [--dport <port>] [--runner ssh|exec] [--json]")
	}
	devices, err := store.ReadJSONL(*storePath)
	if err != nil {
		return err
	}
	svc := diag.NewService(devices, selectRunner(*runnerName, transport.SSHConfig{}), diag.WithDefaultRunner(*runnerName))
	result, err := svc.ValidatePath(context.Background(), pathtrace.Flow{
		Src: *src, Dst: *dst, Proto: *proto, DPort: *dport,
	}, *runnerName)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(result)
	}
	fmt.Fprintf(os.Stdout, "predicted=%s observed=%s agreement=%s checks=%d\n",
		result.PredictedVerdict, result.ObservedVerdict, result.Agreement, len(result.Checks))
	for _, check := range result.Checks {
		fmt.Fprintf(os.Stdout, "  %s ping %s -> %s loss=%.0f%% rtt=%.0fms\n",
			check.FromDevice, check.Target, check.Observed, check.Result.LossPct, check.Result.RTTAvgMs)
	}
	return nil
}

func diagCmd(args []string) error {
	fs := flag.NewFlagSet("diag", flag.ContinueOnError)
	storePath := fs.String("store", "", "JSONL inventory store")
	target := fs.String("target", "", "device hostname or ip:<addr>")
	ping := fs.String("ping", "", "ping destination")
	count := fs.Int("count", 5, "ping count")
	traceroute := fs.String("traceroute", "", "traceroute destination")
	show := fs.String("show", "", "show command")
	execCmd := fs.String("exec", "", "exec command (requires approval)")
	approve := fs.String("approve", "", "approval token for exec")
	runnerName := fs.String("runner", "ssh", "runner: ssh or exec")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("usage: netc diag --target <host|ip:addr> [--store store.jsonl] (--ping dst | --traceroute dst | --show \"...\" | --exec \"...\" [--approve token]) [--runner ssh|exec] [--json]")
	}
	var devices []ir.Device
	if *storePath != "" {
		var err error
		devices, err = store.ReadJSONL(*storePath)
		if err != nil {
			return err
		}
	}
	svc := diag.NewService(devices, selectRunner(*runnerName, transport.SSHConfig{}), diag.WithDefaultRunner(*runnerName))
	req := diag.DiagRequest{Target: *target, Runner: *runnerName, ApprovalToken: *approve}
	switch {
	case *ping != "":
		req.Command = "ping"
		req.Args = diag.DiagArgs{Dst: *ping, Count: *count}
	case *traceroute != "":
		req.Command = "traceroute"
		req.Args = diag.DiagArgs{Dst: *traceroute}
	case *show != "":
		req.Command = "show"
		req.Args = diag.DiagArgs{Raw: *show}
	case *execCmd != "":
		req.Command = "exec"
		req.Args = diag.DiagArgs{Raw: *execCmd}
	default:
		return fmt.Errorf("specify one of --ping, --traceroute, --show, or --exec")
	}
	result, err := svc.Diagnose(context.Background(), req)
	if err != nil && result.Status == "" {
		return err
	}
	if *jsonOut {
		return printJSON(result)
	}
	writeDiagText(os.Stdout, result)
	return nil
}

func selectRunner(name string, sshCfg transport.SSHConfig) diag.Runner {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "exec":
		return transport.NewExecRunner()
	case "simulate":
		return diag.NewFakeRunner()
	default:
		return transport.NewSSHRunner(sshCfg)
	}
}

func buildDiagService(devices []ir.Device, runnerName string, sshCfg transport.SSHConfig, creds diag.CredRef, managementIPs map[string]string) *diag.Service {
	opts := []diag.Option{diag.WithDefaultRunner(runnerName)}
	if len(managementIPs) > 0 {
		opts = append(opts, diag.WithManagementIPs(managementIPs))
	}
	if creds.Username != "" || creds.Secret != "" {
		opts = append(opts, diag.WithDefaultCreds(creds))
	}
	return diag.NewService(devices, selectRunner(runnerName, sshCfg), opts...)
}

func managementIPsFromTargets(targets []guard.Target) map[string]string {
	out := make(map[string]string, len(targets))
	for _, target := range targets {
		if target.Device == "" || target.ManagementIP == "" {
			continue
		}
		out[strings.ToLower(target.Device)] = target.ManagementIP
	}
	return out
}

func writeDiagText(w io.Writer, res diag.DiagResult) {
	fmt.Fprintf(w, "target=%s vendor=%s command=%s class=%s status=%s\n", res.Target, res.Vendor, res.Command, res.Class, res.Status)
	if res.RenderedCommand != "" {
		fmt.Fprintf(w, "rendered=%s\n", res.RenderedCommand)
	}
	if res.Approval != nil && res.Approval.Reason != "" {
		fmt.Fprintf(w, "approval=%s\n", res.Approval.Reason)
	}
	if res.RawOutput != "" {
		fmt.Fprintln(w, res.RawOutput)
	}
	if res.Parsed != nil && res.Parsed.Ping != nil {
		p := res.Parsed.Ping
		fmt.Fprintf(w, "ping sent=%d recv=%d loss=%.0f%% rtt=%.0f/%.0f/%.0f ms\n",
			p.Sent, p.Received, p.LossPct, p.RTTMinMs, p.RTTAvgMs, p.RTTMaxMs)
	}
}

func serveCmd(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	input := fs.String("input", "", "config file, glob, directory, or JSONL inventory")
	discoveryPath := fs.String("discovery", "", "optional discovery JSONL facts from netc discover")
	vendor := fs.String("vendor", "cisco", "vendor parser for config input: cisco, juniper, auto")
	policyPath := fs.String("policy", "", "JSON policy file")
	addr := fs.String("addr", "127.0.0.1:8787", "HTTP listen address")
	runnerName := fs.String("runner", "simulate", "diag runner: ssh, exec, or simulate")
	knownHosts := fs.String("known-hosts", "", "SSH known_hosts file")
	insecureHostKey := fs.Bool("insecure-host-key", false, "skip SSH host key verification")
	targetsPath := fs.String("targets", "", "optional guard targets JSONL for management IP resolution")
	diagUser := fs.String("diag-user", "", "SSH username for diag")
	diagSecret := fs.String("diag-secret", "", "SSH password for diag")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("usage: netc serve --input <config|glob|dir|inventory.jsonl> [--addr 127.0.0.1:8787] [--runner ssh|exec|simulate]")
	}
	devices, err := loadDevices(*vendor, *input)
	if err != nil {
		return err
	}
	var discoveryFacts []ir.DiscoveryFact
	if *discoveryPath != "" {
		discoveryFacts, err = store.ReadRecordsJSONL[ir.DiscoveryFact](*discoveryPath)
		if err != nil {
			return err
		}
	}
	policy, err := policyFromFlags(*policyPath, "", "", "")
	if err != nil {
		return err
	}
	var managementIPs map[string]string
	if *targetsPath != "" {
		targets, err := guard.ReadTargets(*targetsPath)
		if err != nil {
			return err
		}
		managementIPs = managementIPsFromTargets(targets)
	}
	sshCfg := transport.SSHConfig{
		KnownHostsFile:  *knownHosts,
		InsecureHostKey: *insecureHostKey,
	}
	diagSvc := buildDiagService(devices, *runnerName, sshCfg, diag.CredRef{
		Username: *diagUser,
		Secret:   *diagSecret,
	}, managementIPs)
	fmt.Fprintf(os.Stderr, "serving %d devices, %d discovery facts, diag runner=%s at http://%s\n", len(devices), len(discoveryFacts), *runnerName, *addr)
	return http.ListenAndServe(*addr, server.New(devices, policy).
		WithVendors(parser.Vendors()).
		WithDiscoveryFacts(discoveryFacts).
		WithDiag(diagSvc).
		Handler())
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
	if len(files) == 0 {
		if strings.HasSuffix(path, ".jsonl") {
			return []string{path}, nil
		}
		if looksLikeInputPath(path) {
			if _, err := os.Stat(path); err != nil {
				if os.IsNotExist(err) {
					return nil, fmt.Errorf("fichier ou repertoire introuvable: %s (generez un inventaire: netc ingest --input ./testdata/corpus --vendor auto --out inventory.jsonl)", path)
				}
				return nil, err
			}
			return nil, fmt.Errorf("aucun fichier input trouve dans %s", path)
		}
	}
	return files, nil
}

func looksLikeInputPath(path string) bool {
	if strings.Contains(path, "/") || strings.Contains(path, `\`) {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl", ".cfg", ".conf", ".set", ".rsc", ".yaml", ".yml", ".json", ".txt":
		return true
	}
	return strings.Contains(path, ".")
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
	Role     string      `json:"role,omitempty"`
	Summary  string      `json:"summary"`
	Evidence ir.Evidence `json:"evidence"`
}

func briefResults(results []query.Result) []briefResult {
	out := make([]briefResult, 0, len(results))
	for _, result := range results {
		out = append(out, briefResult{
			Type:     result.Type,
			Device:   result.Device,
			Role:     result.Role,
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
		devices, err := store.ReadJSONL(inputs[0])
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("inventaire introuvable: %s (generez-le: netc ingest --input ./testdata/corpus --vendor auto --out %s)", inputs[0], inputs[0])
			}
			return nil, err
		}
		return devices, nil
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

func writePathText(w io.Writer, p pathtrace.Path) {
	for i, hop := range p.Hops {
		via := hop.NextHop
		if via == "" {
			via = "-"
		}
		fmt.Fprintf(w, "%d. %s ingress=%s egress=%s next_hop=%s", i+1, hop.Device, emptyDash(hop.IngressIface), emptyDash(hop.EgressIface), via)
		if hop.IngressZone != "" || hop.EgressZone != "" {
			fmt.Fprintf(w, " zones=%s->%s", emptyDash(hop.IngressZone), emptyDash(hop.EgressZone))
		}
		if hop.RouteMatch != nil {
			fmt.Fprintf(w, " route=%s", hop.RouteMatch.Destination)
		}
		if hop.ACLMatch != nil {
			fmt.Fprintf(w, " acl=%s", hop.ACLMatch.Action)
		}
		if hop.PolicyMatch != nil {
			fmt.Fprintf(w, " policy=%s:%s", hop.PolicyMatch.Name, hop.PolicyMatch.Action)
		}
		if hop.NATApplied != nil {
			fmt.Fprintf(w, " nat=%s:%s", hop.NATApplied.Name, hop.NATApplied.Kind)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "verdict=%s\n", p.Verdict)
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func writeIndentedJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeDiscoverySummary(w io.Writer, discovered discovery.Result, topo topology.Result) {
	fmt.Fprintf(w, "devices=%d neighbors=%d candidate_links=%d conflicts=%d\n", len(discovered.Devices), len(discovered.Neighbors), len(topo.Links), len(topo.Conflicts))
	for _, link := range topo.Links {
		fmt.Fprintf(w, "%s %s -> %s %s confidence=%.2f sources=%s\n", link.A.Device, link.A.Interface, link.B.Device, link.B.Interface, link.Confidence, strings.Join(link.Sources, ","))
	}
	for _, conflict := range topo.Conflicts {
		fmt.Fprintf(w, "conflict type=%s sources=%s %s\n", conflict.Type, strings.Join(conflict.Sources, ","), conflict.Description)
	}
}

func usage() error {
	fmt.Println("usage: netc <check|collect|diag|diff|discover|ingest|inventory|parse|path|query|serve>")
	return nil
}
