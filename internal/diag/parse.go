package diag

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	ciscoPingStats = regexp.MustCompile(`(?i)(\d+)/(\d+)\s*(?:percent|\)|,|\s)`)
	ciscoPingRate  = regexp.MustCompile(`(?i)Success rate is (\d+) percent \((\d+)/(\d+)\)`)
	ciscoRTT       = regexp.MustCompile(`(?i)min/avg/max\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)`)
	linuxPingStats = regexp.MustCompile(`(?i)(\d+) packets transmitted, (\d+) (?:packets )?received`)
	linuxLoss      = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)% packet loss`)
	linuxRTT       = regexp.MustCompile(`(?i)rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/`)
	trHopLine      = regexp.MustCompile(`^\s*(\d+)\s+([\d.]+\s+ms|\*|\s)+([\d.]+|[\w.-]+)`)
)

func parseOutput(kind, output string) *Parsed {
	switch kind {
	case "ping":
		if p := parsePing(output); p != nil {
			return &Parsed{Ping: p}
		}
	case "traceroute":
		if p := parseTraceroute(output); p != nil {
			return &Parsed{Traceroute: p}
		}
	}
	return nil
}

func parsePing(output string) *ParsedPing {
	if p := parseCiscoPing(output); p != nil {
		return p
	}
	if p := parseLinuxPing(output); p != nil {
		return p
	}
	if p := parseExclamationPing(output); p != nil {
		return p
	}
	return nil
}

func parseCiscoPing(output string) *ParsedPing {
	rate := ciscoPingRate.FindStringSubmatch(output)
	rtt := ciscoRTT.FindStringSubmatch(output)
	if rate == nil && rtt == nil {
		return nil
	}
	p := &ParsedPing{}
	if rate != nil {
		if success, err := strconv.ParseFloat(rate[1], 64); err == nil {
			p.LossPct = 100 - success
		}
		if recv, err := strconv.Atoi(rate[2]); err == nil {
			p.Received = recv
		}
		if sent, err := strconv.Atoi(rate[3]); err == nil {
			p.Sent = sent
		}
	}
	if rtt != nil {
		p.RTTMinMs = parseFloat(rtt[1])
		p.RTTAvgMs = parseFloat(rtt[2])
		p.RTTMaxMs = parseFloat(rtt[3])
	}
	if p.Sent == 0 && p.Received > 0 {
		p.Sent = p.Received
	}
	return p
}

func parseExclamationPing(output string) *ParsedPing {
	ex := strings.Count(output, "!")
	dot := strings.Count(output, ".")
	q := strings.Count(output, "?")
	sent := ex + dot + q
	if sent == 0 {
		return nil
	}
	loss := float64(dot+q) * 100 / float64(sent)
	return &ParsedPing{
		Sent:     sent,
		Received: ex,
		LossPct:  loss,
	}
}

func parseLinuxPing(output string) *ParsedPing {
	stats := linuxPingStats.FindStringSubmatch(output)
	if stats == nil {
		return nil
	}
	p := &ParsedPing{
		Sent:     atoi(stats[1]),
		Received: atoi(stats[2]),
	}
	if loss := linuxLoss.FindStringSubmatch(output); loss != nil {
		p.LossPct = parseFloat(loss[1])
	} else if p.Sent > 0 {
		p.LossPct = float64(p.Sent-p.Received) * 100 / float64(p.Sent)
	}
	if rtt := linuxRTT.FindStringSubmatch(output); rtt != nil {
		p.RTTMinMs = parseFloat(rtt[1])
		p.RTTAvgMs = parseFloat(rtt[2])
		p.RTTMaxMs = parseFloat(rtt[3])
	}
	return p
}

func parseTraceroute(output string) *ParsedTraceroute {
	lines := strings.Split(output, "\n")
	var hops []ParsedHop
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ttl, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		host := fields[len(fields)-1]
		if strings.HasSuffix(host, "ms") && len(fields) >= 3 {
			host = fields[len(fields)-2]
		}
		var rtt float64
		for _, f := range fields[1:] {
			f = strings.TrimSuffix(f, "ms")
			if v := parseFloat(f); v > 0 {
				rtt = v
				break
			}
		}
		hops = append(hops, ParsedHop{TTL: ttl, Host: host, RTTMs: rtt})
	}
	if len(hops) == 0 {
		return nil
	}
	return &ParsedTraceroute{Hops: hops}
}

func parseFloat(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v
}

func atoi(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}

func observedFromPing(p *ParsedPing) string {
	if p == nil {
		return ObservedInconclusive
	}
	if p.Received > 0 && p.LossPct < 100 {
		return ObservedReachable
	}
	if p.LossPct >= 100 || p.Received == 0 {
		return ObservedUnreachable
	}
	return ObservedInconclusive
}
