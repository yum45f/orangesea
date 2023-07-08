// the package nsid is a utility library for NSID

package nsid

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	rpattern = `^[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+((\.\*)|(\.([a-zA-Z]{1,63}))((\.\*)|(#[a-zA-Z]{1,63}))?)$`
)

// NSID is a struct for NSID
type NSID struct {
	dsegments []string // domain segments
	name      string   // name
	fragment  string   // fragment
	glob      bool     // glob; true if NSID has glob (wildcard)
}

func NewNSID(nsidStr string) (*NSID, error) {
	if len(nsidStr) == 0 {
		return nil, fmt.Errorf("invalid NSID: %s; empty", nsidStr)
	}
	if len(nsidStr) > 317 {
		return nil, fmt.Errorf("invalid NSID: %s; too long", nsidStr)
	}

	r := regexp.MustCompile(rpattern)
	if !r.MatchString(nsidStr) {
		return nil, fmt.Errorf("invalid NSID: %s; wrong pattern", nsidStr)
	}

	nsid := new(NSID)

	splited := strings.Split(nsidStr, "#")
	if len(splited) > 2 {
		return nil, fmt.Errorf("invalid NSID: %s; multi-fragment", nsidStr)
	}
	if len(splited) == 2 {
		nsid.fragment = splited[1]
	}

	splited = strings.Split(splited[0], ".")
	if len(splited) < 3 {
		return nil, fmt.Errorf("invalid NSID: %s; segments are too few", nsidStr)
	}

	nsid.dsegments = splited[:len(splited)-1]
	for i, dsegment := range nsid.dsegments {
		if len(dsegment) > 63 {
			return nil, fmt.Errorf("invalid NSID: %s; domain segment is too long", nsidStr)
		}
		nsid.dsegments[i] = strings.ToLower(dsegment)
	}

	nsid.name = splited[len(splited)-1]

	if nsid.name == "*" {
		if nsid.fragment != "" {
			return nil, fmt.Errorf("invalid NSID: %s; wildcard NSID cannot have fragment", nsidStr)
		}
		nsid.glob = true
	}

	if len(strings.Join(nsid.dsegments, ".")) > 253 {
		return nil, fmt.Errorf("invalid NSID: %s; domain segments are too long", nsidStr)
	}
	if len(nsid.name) > 63 {
		return nil, fmt.Errorf("invalid NSID: %s; name is too long", nsidStr)
	}

	return nsid, nil
}

// String returns string representation of NSID
func (nsid *NSID) String() string {
	if nsid.fragment == "" {
		return strings.Join(nsid.dsegments, ".") + "." + nsid.name
	}
	return strings.Join(nsid.dsegments, ".") + "." + nsid.name + "#" + nsid.fragment
}

// Name returns the name segment of NSID
func (nsid *NSID) Name() string {
	return nsid.name
}

// Fragment returns the fragment of NSID
func (nsid *NSID) Fragment() string {
	return nsid.fragment
}

// Glob returns true if NSID has glob (wildcard)
// If NSID has glob, the name segment must be "*"
func (nsid *NSID) Glob() bool {
	return nsid.glob
}

// DSegments returns the domain segments of NSID
// The domain segments do not include the name segment
func (nsid *NSID) DSegments() []string {
	return nsid.dsegments
}
