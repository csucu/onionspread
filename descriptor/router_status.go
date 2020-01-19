package descriptor

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/csucu/onionspread/common"
)

// RouterFlags represents the possible flags a router status can have
type RouterFlags struct {
	Authority bool
	BadExit   bool
	Exit      bool
	Fast      bool
	Guard     bool
	HSDir     bool
	Named     bool
	Stable    bool
	Running   bool
	Unnamed   bool
	V2Dir     bool
	Valid     bool
}

// RouterStatusEntry represents a router status entry as its defined in
// https://gitweb.torproject.org/torspec.git/plain/dir-spec.txt
type RouterStatusEntry struct {
	Nickname    string
	Fingerprint string
	Digest      string
	Published   time.Time
	Address     net.IP
	ORPort      int
	DirPort     int
	Flags       RouterFlags
	Version     string
	Bandwidth   int
	Accept      bool
	PortList    string
}

func ParseRouterStatusEntriesRaw(data string) ([]RouterStatusEntry, error) {
	var entries []RouterStatusEntry
	var raw = data
	var EOF bool
	var err error

	for {
		var entry *RouterStatusEntry
		entry, raw, EOF, err = extractRouterStatusEntry(raw)
		if err != nil {
			return entries, err
		}

		entries = append(entries, *entry)

		if EOF {
			break
		}
	}

	return entries, nil
}

func extractRouterStatusEntry(data string) (*RouterStatusEntry, string, bool, error) {
	if len(data) == 0 {
		return nil, data, true, nil
	}

	start := 0
	if !strings.HasPrefix(data, string("r ")) {
		start = strings.Index(data, string("\nr "))
		if start < 0 {
			return nil, data, false, errors.New("cannot find the start of the router status entry")
		}
		start += 1
	}

	end := strings.Index(data[start:], string("\nr "))
	if end >= 0 {
		var entry, err = parseRouterStatusEntry(data[start : start+end+1])
		if err != nil {
			return nil, "", false, err
		}
		return entry, data[start+end+1:], false, nil
	}

	entry, err := parseRouterStatusEntry(data[start:])
	if err != nil {
		return nil, "", true, err
	}

	return entry, "", true, nil
}

func parseRouterStatusEntry(routerStatusEntryRaw string) (*RouterStatusEntry, error) {
	routerStatusEntry := RouterStatusEntry{}
	lines := strings.Split(routerStatusEntryRaw, "\n")
	for _, line := range lines {
		var err error

		words := strings.Split(line, " ")
		switch words[0] {
		case "r":
			//r" SP nickname SP identity SP digest SP publication SP IP SP ORPort SP DirPort NL
			routerStatusEntry.Nickname = words[1]

			routerStatusEntry.Fingerprint, err = common.Base64ToHex(words[2])
			if err != nil {
				return nil, err
			}

			routerStatusEntry.Digest, err = common.Base64ToHex(words[3])
			if err != nil {
				return nil, err
			}

			pubTime, err := time.Parse("2006-01-02 15:04:05", strings.Join(words[4:6], " "))
			if err != nil {
				return nil, err
			}

			routerStatusEntry.Published = pubTime
			routerStatusEntry.Address = net.ParseIP(words[6])

			routerStatusEntry.ORPort, err = strconv.Atoi(words[7])
			if err != nil {
				return nil, err
			}

			routerStatusEntry.DirPort, err = strconv.Atoi(words[8])
			if err != nil {
				return nil, err
			}

		case "s":
			routerStatusEntry.Flags = parseFlags(words[1:])
		case "v":
			routerStatusEntry.Version = words[2]
		case "w":
			routerStatusEntry.Bandwidth, err = strconv.Atoi(strings.Split(words[1], "=")[1])
			if err != nil {
				return nil, err
			}
		case "p":
			if words[1] == "accept" {
				routerStatusEntry.Accept = true
			} else {
				routerStatusEntry.Accept = false
			}

			routerStatusEntry.PortList = strings.Join(words[2:], " ")
		}
	}

	return &routerStatusEntry, nil
}

func parseFlags(flags []string) RouterFlags {
	parsedflags := RouterFlags{}
	for _, flag := range flags {
		switch flag {
		case "Authority":
			parsedflags.Authority = true
		case "BadExit":
			parsedflags.BadExit = true
		case "Exit":
			parsedflags.Exit = true
		case "Fast":
			parsedflags.Fast = true
		case "Guard":
			parsedflags.Guard = true
		case "HSDir":
			parsedflags.HSDir = true
		case "Named":
			parsedflags.Named = true
		case "Stable":
			parsedflags.Stable = true
		case "Running":
			parsedflags.Running = true
		case "Unnamed":
			parsedflags.Unnamed = true
		case "V2Dir":
			parsedflags.V2Dir = true
		case "Valid":
			parsedflags.Valid = true
		}
	}

	return parsedflags
}
