package guard

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultVersion = "collect-guard-v1"
	ModeInventory  = "inventory_only"
)

type Config struct {
	Version           string            `json:"version"`
	AllowCIDRs        []string          `json:"allow_cidrs"`
	DenyCIDRs         []string          `json:"deny_cidrs"`
	AllowIPv6CIDRs    []string          `json:"allow_ipv6_cidrs"`
	DenyIPv6CIDRs     []string          `json:"deny_ipv6_cidrs"`
	RequireAllowMatch bool              `json:"require_allow_match"`
	Targets           TargetPolicy      `json:"targets"`
	Commands          CommandPolicy     `json:"commands"`
	Limits            Limits            `json:"limits"`
	Plan              PlanPolicy        `json:"plan"`
	NeighborExpansion NeighborExpansion `json:"neighbor_expansion"`
	Audit             AuditPolicy       `json:"audit"`
}

type TargetPolicy struct {
	Mode                     string `json:"mode"`
	RequireDeviceID          bool   `json:"require_device_id"`
	RequireManagementIP      bool   `json:"require_management_ip"`
	RejectNeighborsAsTargets bool   `json:"reject_neighbors_as_targets"`
}

type CommandPolicy struct {
	Allow        []string `json:"allow"`
	DenyPatterns []string `json:"deny_patterns"`
}

type Limits struct {
	MaxTargetsPerRun        int  `json:"max_targets_per_run"`
	MaxTargetsPerCIDR       int  `json:"max_targets_per_cidr"`
	MaxParallelSessions     int  `json:"max_parallel_sessions"`
	PerTargetTimeoutSeconds int  `json:"per_target_timeout_seconds"`
	GlobalTimeoutSeconds    int  `json:"global_timeout_seconds"`
	RetryCount              int  `json:"retry_count"`
	RequireExplicitTargets  bool `json:"require_explicit_targets"`
	ForbidPingSweep         bool `json:"forbid_ping_sweep"`
	ForbidPortScan          bool `json:"forbid_port_scan"`
	ForbidSubnetExpansion   bool `json:"forbid_subnet_expansion"`
}

type PlanPolicy struct {
	RequireDryRun        bool `json:"require_dry_run"`
	RequirePlanHash      bool `json:"require_plan_hash"`
	WriteRejectedTargets bool `json:"write_rejected_targets"`
}

type NeighborExpansion struct {
	Enabled                   bool     `json:"enabled"`
	RequireHumanPromotion     bool     `json:"require_human_promotion"`
	PromoteOnlyIfInAllowCIDRs bool     `json:"promote_only_if_in_allow_cidrs"`
	PromoteOnlyIfSeenBy       []string `json:"promote_only_if_seen_by"`
	MinConfidence             float64  `json:"min_confidence"`
}

type AuditPolicy struct {
	LogFile             string `json:"log_file"`
	LogAllowed          bool   `json:"log_allowed"`
	LogRejected         bool   `json:"log_rejected"`
	RedactSecrets       bool   `json:"redact_secrets"`
	IncludeGuardVersion bool   `json:"include_guard_version"`
}

type Target struct {
	Device       string   `json:"device"`
	ManagementIP string   `json:"management_ip"`
	Source       string   `json:"source,omitempty"`
	Commands     []string `json:"commands,omitempty"`
}

type Decision struct {
	Target           Target            `json:"target"`
	Allowed          bool              `json:"allowed"`
	Reasons          []string          `json:"reasons,omitempty"`
	MatchedAllowCIDR string            `json:"matched_allow_cidr,omitempty"`
	MatchedDenyCIDR  string            `json:"matched_deny_cidr,omitempty"`
	Commands         []CommandDecision `json:"commands,omitempty"`
}

type CommandDecision struct {
	Command string `json:"command"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type Plan struct {
	Version      string      `json:"version"`
	GuardVersion string      `json:"guard_version"`
	Summary      PlanSummary `json:"summary"`
	Targets      []Decision  `json:"targets"`
	SHA256       string      `json:"sha256"`
}

type PlanSummary struct {
	TargetsInput     int `json:"targets_input"`
	Allowed          int `json:"allowed"`
	Rejected         int `json:"rejected"`
	CommandsAllowed  int `json:"commands_allowed"`
	CommandsRejected int `json:"commands_rejected"`
}

type compiledConfig struct {
	Config
	allow       []netip.Prefix
	deny        []netip.Prefix
	commandDeny []*regexp.Regexp
}

func DefaultConfig() Config {
	return Config{
		Version:           DefaultVersion,
		AllowCIDRs:        []string{},
		DenyCIDRs:         []string{},
		DenyIPv6CIDRs:     []string{"::/0"},
		RequireAllowMatch: true,
		Targets: TargetPolicy{
			Mode:                     ModeInventory,
			RequireDeviceID:          true,
			RequireManagementIP:      true,
			RejectNeighborsAsTargets: true,
		},
		Commands: CommandPolicy{
			Allow: []string{
				"show lldp neighbors detail",
				"show cdp neighbors detail",
				"show arp",
				"show mac address-table",
				"show ip interface brief",
				"show vlan",
				"show running-config",
			},
			DenyPatterns: []string{"^conf", "^configure", "^write", "^copy", "^delete", "^reload", "^clear", "^debug", "^test"},
		},
		Limits: Limits{
			MaxTargetsPerRun:        50,
			MaxTargetsPerCIDR:       20,
			MaxParallelSessions:     4,
			PerTargetTimeoutSeconds: 20,
			GlobalTimeoutSeconds:    900,
			RetryCount:              1,
			RequireExplicitTargets:  true,
			ForbidPingSweep:         true,
			ForbidPortScan:          true,
			ForbidSubnetExpansion:   true,
		},
		Plan: PlanPolicy{RequireDryRun: true, RequirePlanHash: true, WriteRejectedTargets: true},
		NeighborExpansion: NeighborExpansion{
			Enabled:                   false,
			RequireHumanPromotion:     true,
			PromoteOnlyIfInAllowCIDRs: true,
			PromoteOnlyIfSeenBy:       []string{"lldp", "cdp"},
			MinConfidence:             0.95,
		},
		Audit: AuditPolicy{LogAllowed: true, LogRejected: true, RedactSecrets: true, IncludeGuardVersion: true},
	}
}

func ReadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Config{}, fmt.Errorf("%s: guard config is empty", path)
	}
	if trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &cfg); err != nil {
			return Config{}, fmt.Errorf("%s: %w", path, err)
		}
		return withDefaults(cfg), nil
	}
	parsed, err := parseSimpleYAML(trimmed)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	overlayConfig(&cfg, parsed)
	return withDefaults(cfg), nil
}

func ReadTargets(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%s: targets file is empty", path)
	}
	if trimmed[0] == '[' {
		var targets []Target
		if err := json.Unmarshal(trimmed, &targets); err != nil {
			return nil, err
		}
		return targets, nil
	}
	var targets []Target
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var target Target
		if err := json.Unmarshal([]byte(text), &target); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		targets = append(targets, target)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

func BuildPlan(cfg Config, targets []Target) (Plan, error) {
	compiled, err := compile(cfg)
	if err != nil {
		return Plan{}, err
	}
	decisions := make([]Decision, 0, len(targets))
	for _, target := range targets {
		decision := compiled.CheckTarget(target)
		decisions = append(decisions, decision)
	}
	applyRunLimits(compiled, decisions)
	sort.SliceStable(decisions, func(i, j int) bool {
		return decisionKey(decisions[i]) < decisionKey(decisions[j])
	})
	plan := Plan{
		Version:      "collect-plan-v1",
		GuardVersion: compiled.Version,
		Targets:      decisions,
	}
	plan.Summary = summarize(decisions, len(targets))
	hash, err := hashPlan(plan)
	if err != nil {
		return Plan{}, err
	}
	plan.SHA256 = hash
	return plan, nil
}

func WriteAudit(path string, plan Plan, cfg Config) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, decision := range plan.Targets {
		if decision.Allowed && !cfg.Audit.LogAllowed {
			continue
		}
		if !decision.Allowed && !cfg.Audit.LogRejected {
			continue
		}
		record := map[string]any{
			"target":             decision.Target.ManagementIP,
			"device":             decision.Target.Device,
			"decision":           allowedText(decision.Allowed),
			"reasons":            decision.Reasons,
			"matched_allow_cidr": decision.MatchedAllowCIDR,
			"matched_deny_cidr":  decision.MatchedDenyCIDR,
		}
		if cfg.Audit.IncludeGuardVersion {
			record["guard"] = plan.GuardVersion
		}
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func (cfg compiledConfig) CheckTarget(target Target) Decision {
	decision := Decision{Target: target}
	if cfg.Targets.RequireDeviceID && strings.TrimSpace(target.Device) == "" {
		decision.Reasons = append(decision.Reasons, "missing device id")
	}
	if cfg.Targets.RequireManagementIP && strings.TrimSpace(target.ManagementIP) == "" {
		decision.Reasons = append(decision.Reasons, "missing management ip")
	}
	if cfg.Targets.RejectNeighborsAsTargets && strings.EqualFold(target.Source, "neighbor") {
		decision.Reasons = append(decision.Reasons, "neighbor targets require human promotion")
	}
	if cfg.Targets.Mode != "" && cfg.Targets.Mode != ModeInventory {
		decision.Reasons = append(decision.Reasons, "unsupported target mode "+cfg.Targets.Mode)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(target.ManagementIP))
	if target.ManagementIP != "" && err != nil {
		decision.Reasons = append(decision.Reasons, "invalid management ip")
	}
	if err == nil {
		for _, prefix := range cfg.deny {
			if prefix.Contains(ip) {
				decision.MatchedDenyCIDR = prefix.String()
				decision.Reasons = append(decision.Reasons, "matched deny cidr")
				break
			}
		}
		for _, prefix := range cfg.allow {
			if prefix.Contains(ip) {
				decision.MatchedAllowCIDR = prefix.String()
				break
			}
		}
		if cfg.RequireAllowMatch && decision.MatchedAllowCIDR == "" {
			decision.Reasons = append(decision.Reasons, "no allow_cidr match")
		}
	}
	commands := target.Commands
	if len(commands) == 0 {
		commands = append([]string(nil), cfg.Commands.Allow...)
	}
	for _, command := range commands {
		cd := cfg.CheckCommand(command)
		decision.Commands = append(decision.Commands, cd)
		if !cd.Allowed {
			decision.Reasons = append(decision.Reasons, "command rejected: "+command)
		}
	}
	decision.Allowed = len(decision.Reasons) == 0
	return decision
}

func (cfg compiledConfig) CheckCommand(command string) CommandDecision {
	command = strings.TrimSpace(command)
	for _, re := range cfg.commandDeny {
		if re.MatchString(command) {
			return CommandDecision{Command: command, Allowed: false, Reason: "deny pattern " + re.String()}
		}
	}
	for _, allowed := range cfg.Commands.Allow {
		if command == allowed {
			return CommandDecision{Command: command, Allowed: true}
		}
	}
	return CommandDecision{Command: command, Allowed: false, Reason: "not in read-only allowlist"}
}

func compile(cfg Config) (compiledConfig, error) {
	cfg = withDefaults(cfg)
	out := compiledConfig{Config: cfg}
	for _, cidr := range append(cfg.AllowCIDRs, cfg.AllowIPv6CIDRs...) {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return compiledConfig{}, fmt.Errorf("allow cidr %q: %w", cidr, err)
		}
		out.allow = append(out.allow, prefix)
	}
	for _, cidr := range append(cfg.DenyCIDRs, cfg.DenyIPv6CIDRs...) {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return compiledConfig{}, fmt.Errorf("deny cidr %q: %w", cidr, err)
		}
		out.deny = append(out.deny, prefix)
	}
	for _, pattern := range cfg.Commands.DenyPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return compiledConfig{}, fmt.Errorf("deny pattern %q: %w", pattern, err)
		}
		out.commandDeny = append(out.commandDeny, re)
	}
	return out, nil
}

func applyRunLimits(cfg compiledConfig, decisions []Decision) {
	allowedSeen := 0
	perCIDR := map[string]int{}
	for i := range decisions {
		if !decisions[i].Allowed {
			continue
		}
		allowedSeen++
		if cfg.Limits.MaxTargetsPerRun > 0 && allowedSeen > cfg.Limits.MaxTargetsPerRun {
			decisions[i].Allowed = false
			decisions[i].Reasons = append(decisions[i].Reasons, "max_targets_per_run exceeded")
			continue
		}
		cidr := decisions[i].MatchedAllowCIDR
		if cidr != "" {
			perCIDR[cidr]++
			if cfg.Limits.MaxTargetsPerCIDR > 0 && perCIDR[cidr] > cfg.Limits.MaxTargetsPerCIDR {
				decisions[i].Allowed = false
				decisions[i].Reasons = append(decisions[i].Reasons, "max_targets_per_cidr exceeded")
			}
		}
	}
}

func summarize(decisions []Decision, inputs int) PlanSummary {
	summary := PlanSummary{TargetsInput: inputs}
	for _, decision := range decisions {
		if decision.Allowed {
			summary.Allowed++
		} else {
			summary.Rejected++
		}
		for _, command := range decision.Commands {
			if command.Allowed {
				summary.CommandsAllowed++
			} else {
				summary.CommandsRejected++
			}
		}
	}
	return summary
}

func hashPlan(plan Plan) (string, error) {
	plan.SHA256 = ""
	data, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func VerifyPlanHash(plan Plan, expected string) error {
	hash, err := hashPlan(plan)
	if err != nil {
		return err
	}
	if hash != expected {
		return fmt.Errorf("plan hash mismatch: got %s want %s", hash, expected)
	}
	return nil
}

func ReadPlan(path string) (Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func allowedText(ok bool) string {
	if ok {
		return "allowed"
	}
	return "rejected"
}

func decisionKey(decision Decision) string {
	return strings.Join([]string{decision.Target.Device, decision.Target.ManagementIP}, "\x00")
}

func withDefaults(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.Version == "" {
		cfg.Version = defaults.Version
	}
	if len(cfg.DenyCIDRs) == 0 {
		cfg.DenyCIDRs = defaults.DenyCIDRs
	}
	if len(cfg.DenyIPv6CIDRs) == 0 {
		cfg.DenyIPv6CIDRs = defaults.DenyIPv6CIDRs
	}
	if cfg.Targets.Mode == "" {
		cfg.Targets.Mode = defaults.Targets.Mode
	}
	cfg.Targets.RequireDeviceID = cfg.Targets.RequireDeviceID || defaults.Targets.RequireDeviceID
	cfg.Targets.RequireManagementIP = cfg.Targets.RequireManagementIP || defaults.Targets.RequireManagementIP
	cfg.Targets.RejectNeighborsAsTargets = cfg.Targets.RejectNeighborsAsTargets || defaults.Targets.RejectNeighborsAsTargets
	if cfg.Limits.MaxTargetsPerRun == 0 {
		cfg.Limits.MaxTargetsPerRun = defaults.Limits.MaxTargetsPerRun
	}
	if cfg.Limits.MaxTargetsPerCIDR == 0 {
		cfg.Limits.MaxTargetsPerCIDR = defaults.Limits.MaxTargetsPerCIDR
	}
	if cfg.Limits.MaxParallelSessions == 0 {
		cfg.Limits.MaxParallelSessions = defaults.Limits.MaxParallelSessions
	}
	if cfg.Limits.PerTargetTimeoutSeconds == 0 {
		cfg.Limits.PerTargetTimeoutSeconds = defaults.Limits.PerTargetTimeoutSeconds
	}
	if cfg.Limits.GlobalTimeoutSeconds == 0 {
		cfg.Limits.GlobalTimeoutSeconds = defaults.Limits.GlobalTimeoutSeconds
	}
	if cfg.Limits.RetryCount == 0 {
		cfg.Limits.RetryCount = defaults.Limits.RetryCount
	}
	cfg.Limits.RequireExplicitTargets = cfg.Limits.RequireExplicitTargets || defaults.Limits.RequireExplicitTargets
	cfg.Limits.ForbidPingSweep = cfg.Limits.ForbidPingSweep || defaults.Limits.ForbidPingSweep
	cfg.Limits.ForbidPortScan = cfg.Limits.ForbidPortScan || defaults.Limits.ForbidPortScan
	cfg.Limits.ForbidSubnetExpansion = cfg.Limits.ForbidSubnetExpansion || defaults.Limits.ForbidSubnetExpansion
	if len(cfg.Commands.Allow) == 0 {
		cfg.Commands.Allow = defaults.Commands.Allow
	}
	if len(cfg.Commands.DenyPatterns) == 0 {
		cfg.Commands.DenyPatterns = defaults.Commands.DenyPatterns
	}
	cfg.Plan.RequireDryRun = cfg.Plan.RequireDryRun || defaults.Plan.RequireDryRun
	cfg.Plan.RequirePlanHash = cfg.Plan.RequirePlanHash || defaults.Plan.RequirePlanHash
	cfg.Plan.WriteRejectedTargets = cfg.Plan.WriteRejectedTargets || defaults.Plan.WriteRejectedTargets
	if cfg.NeighborExpansion.MinConfidence == 0 {
		cfg.NeighborExpansion.MinConfidence = defaults.NeighborExpansion.MinConfidence
	}
	cfg.NeighborExpansion.RequireHumanPromotion = cfg.NeighborExpansion.RequireHumanPromotion || defaults.NeighborExpansion.RequireHumanPromotion
	cfg.NeighborExpansion.PromoteOnlyIfInAllowCIDRs = cfg.NeighborExpansion.PromoteOnlyIfInAllowCIDRs || defaults.NeighborExpansion.PromoteOnlyIfInAllowCIDRs
	if len(cfg.NeighborExpansion.PromoteOnlyIfSeenBy) == 0 {
		cfg.NeighborExpansion.PromoteOnlyIfSeenBy = defaults.NeighborExpansion.PromoteOnlyIfSeenBy
	}
	cfg.Audit.LogAllowed = cfg.Audit.LogAllowed || defaults.Audit.LogAllowed
	cfg.Audit.LogRejected = cfg.Audit.LogRejected || defaults.Audit.LogRejected
	cfg.Audit.RedactSecrets = cfg.Audit.RedactSecrets || defaults.Audit.RedactSecrets
	cfg.Audit.IncludeGuardVersion = cfg.Audit.IncludeGuardVersion || defaults.Audit.IncludeGuardVersion
	cfg.RequireAllowMatch = cfg.RequireAllowMatch || defaults.RequireAllowMatch
	return cfg
}

type yamlNode struct {
	scalars map[string]string
	lists   map[string][]string
}

func parseSimpleYAML(data []byte) (map[string]yamlNode, error) {
	nodes := map[string]yamlNode{"": {scalars: map[string]string{}, lists: map[string][]string{}}}
	var section, listKey string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 && strings.HasSuffix(trimmed, ":") && isYAMLSection(strings.TrimSuffix(trimmed, ":")) {
			section = strings.TrimSuffix(trimmed, ":")
			nodes[section] = yamlNode{scalars: map[string]string{}, lists: map[string][]string{}}
			listKey = ""
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			if listKey == "" {
				return nil, fmt.Errorf("line %d: list item without key", line)
			}
			node := nodes[section]
			node.lists[listKey] = append(node.lists[listKey], unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))))
			nodes[section] = node
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: unsupported yaml line", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		node := nodes[section]
		if value == "" {
			listKey = key
			node.lists[key] = nil
		} else {
			listKey = ""
			node.scalars[key] = unquote(value)
		}
		nodes[section] = node
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

func overlayConfig(cfg *Config, nodes map[string]yamlNode) {
	root := nodes[""]
	cfg.Version = stringValue(root, "version", cfg.Version)
	cfg.AllowCIDRs = listValue(root, "allow_cidrs", cfg.AllowCIDRs)
	cfg.DenyCIDRs = listValue(root, "deny_cidrs", cfg.DenyCIDRs)
	cfg.AllowIPv6CIDRs = listValue(root, "allow_ipv6_cidrs", cfg.AllowIPv6CIDRs)
	cfg.DenyIPv6CIDRs = listValue(root, "deny_ipv6_cidrs", cfg.DenyIPv6CIDRs)
	cfg.RequireAllowMatch = boolValue(root, "require_allow_match", cfg.RequireAllowMatch)

	targets := nodes["targets"]
	cfg.Targets.Mode = stringValue(targets, "mode", cfg.Targets.Mode)
	cfg.Targets.RequireDeviceID = boolValue(targets, "require_device_id", cfg.Targets.RequireDeviceID)
	cfg.Targets.RequireManagementIP = boolValue(targets, "require_management_ip", cfg.Targets.RequireManagementIP)
	cfg.Targets.RejectNeighborsAsTargets = boolValue(targets, "reject_neighbors_as_targets", cfg.Targets.RejectNeighborsAsTargets)

	commands := nodes["commands"]
	cfg.Commands.Allow = listValue(commands, "allow", cfg.Commands.Allow)
	cfg.Commands.DenyPatterns = listValue(commands, "deny_patterns", cfg.Commands.DenyPatterns)

	limits := nodes["limits"]
	cfg.Limits.MaxTargetsPerRun = intValue(limits, "max_targets_per_run", cfg.Limits.MaxTargetsPerRun)
	cfg.Limits.MaxTargetsPerCIDR = intValue(limits, "max_targets_per_cidr", cfg.Limits.MaxTargetsPerCIDR)
	cfg.Limits.MaxParallelSessions = intValue(limits, "max_parallel_sessions", cfg.Limits.MaxParallelSessions)
	cfg.Limits.PerTargetTimeoutSeconds = intValue(limits, "per_target_timeout_seconds", cfg.Limits.PerTargetTimeoutSeconds)
	cfg.Limits.GlobalTimeoutSeconds = intValue(limits, "global_timeout_seconds", cfg.Limits.GlobalTimeoutSeconds)
	cfg.Limits.RetryCount = intValue(limits, "retry_count", cfg.Limits.RetryCount)
	cfg.Limits.RequireExplicitTargets = boolValue(limits, "require_explicit_targets", cfg.Limits.RequireExplicitTargets)
	cfg.Limits.ForbidPingSweep = boolValue(limits, "forbid_ping_sweep", cfg.Limits.ForbidPingSweep)
	cfg.Limits.ForbidPortScan = boolValue(limits, "forbid_port_scan", cfg.Limits.ForbidPortScan)
	cfg.Limits.ForbidSubnetExpansion = boolValue(limits, "forbid_subnet_expansion", cfg.Limits.ForbidSubnetExpansion)

	plan := nodes["plan"]
	cfg.Plan.RequireDryRun = boolValue(plan, "require_dry_run", cfg.Plan.RequireDryRun)
	cfg.Plan.RequirePlanHash = boolValue(plan, "require_plan_hash", cfg.Plan.RequirePlanHash)
	cfg.Plan.WriteRejectedTargets = boolValue(plan, "write_rejected_targets", cfg.Plan.WriteRejectedTargets)

	neighbor := nodes["neighbor_expansion"]
	cfg.NeighborExpansion.Enabled = boolValue(neighbor, "enabled", cfg.NeighborExpansion.Enabled)
	cfg.NeighborExpansion.RequireHumanPromotion = boolValue(neighbor, "require_human_promotion", cfg.NeighborExpansion.RequireHumanPromotion)
	cfg.NeighborExpansion.PromoteOnlyIfInAllowCIDRs = boolValue(neighbor, "promote_only_if_in_allow_cidrs", cfg.NeighborExpansion.PromoteOnlyIfInAllowCIDRs)
	cfg.NeighborExpansion.PromoteOnlyIfSeenBy = listValue(neighbor, "promote_only_if_seen_by", cfg.NeighborExpansion.PromoteOnlyIfSeenBy)
	cfg.NeighborExpansion.MinConfidence = floatValue(neighbor, "min_confidence", cfg.NeighborExpansion.MinConfidence)

	audit := nodes["audit"]
	cfg.Audit.LogFile = stringValue(audit, "log_file", cfg.Audit.LogFile)
	cfg.Audit.LogAllowed = boolValue(audit, "log_allowed", cfg.Audit.LogAllowed)
	cfg.Audit.LogRejected = boolValue(audit, "log_rejected", cfg.Audit.LogRejected)
	cfg.Audit.RedactSecrets = boolValue(audit, "redact_secrets", cfg.Audit.RedactSecrets)
	cfg.Audit.IncludeGuardVersion = boolValue(audit, "include_guard_version", cfg.Audit.IncludeGuardVersion)
}

func isYAMLSection(name string) bool {
	switch name {
	case "targets", "commands", "limits", "plan", "neighbor_expansion", "audit":
		return true
	default:
		return false
	}
}

func stringValue(node yamlNode, key, fallback string) string {
	if node.scalars == nil {
		return fallback
	}
	if value, ok := node.scalars[key]; ok {
		return value
	}
	return fallback
}

func listValue(node yamlNode, key string, fallback []string) []string {
	if node.lists == nil {
		return fallback
	}
	if values, ok := node.lists[key]; ok {
		return values
	}
	return fallback
}

func boolValue(node yamlNode, key string, fallback bool) bool {
	value := stringValue(node, key, "")
	if value == "" {
		return fallback
	}
	return value == "true" || value == "yes"
}

func intValue(node yamlNode, key string, fallback int) int {
	value := stringValue(node, key, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func floatValue(node yamlNode, key string, fallback float64) float64 {
	value := stringValue(node, key, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func unquote(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.Trim(value, `'`)
	return value
}
