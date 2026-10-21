// catalog.go parses issue-catalog/k8s-issue-catalog.yaml — the 1,032-entry
// canonical fault catalogue — into the fields this generator maps onto a
// golden eval case. Only the fields that participate in that mapping are
// declared; the file's other content is read and ignored rather than
// mirrored, so a catalogue field added later does not break this parse.
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Entry is one catalogue entry. The field names are the catalogue's own.
//
// Every one of these except Subsection participates in the mapping onto a
// golden case, which is the whole reason this generator exists rather than
// twenty hand-written JSON files: the catalogue already records, per fault,
// what you observe (Signals), what it could be (RootCauses), whether it
// shows up in the tool surface at all (Silent), and how it is fixed
// (Fix/Channels/Risk). That is most of a golden record already.
type Entry struct {
	ID           string   `yaml:"id"`
	Category     string   `yaml:"category"`
	CategoryName string   `yaml:"category_name"`
	Subsection   string   `yaml:"subsection"`
	Issue        string   `yaml:"issue"`
	Signals      string   `yaml:"signals"`
	Silent       bool     `yaml:"silent"`
	RootCauses   []string `yaml:"root_causes"`
	Fix          string   `yaml:"fix"`
	Channels     []string `yaml:"channels"`
	Risk         string   `yaml:"risk"`
	Autonomy     string   `yaml:"autonomy"`
}

type catalogFile struct {
	SchemaVersion int     `yaml:"schema_version"`
	Entries       []Entry `yaml:"entries"`
}

// LoadCatalog reads and parses the catalogue, preserving file order — every
// selection decision downstream breaks ties on that order, so a regenerated
// corpus is byte-identical as long as the catalogue has not changed.
func LoadCatalog(path string) ([]Entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalogue %s: %w", path, err)
	}
	var cf catalogFile
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		return nil, fmt.Errorf("parse catalogue %s: %w", path, err)
	}
	if len(cf.Entries) == 0 {
		return nil, fmt.Errorf("catalogue %s parsed to zero entries", path)
	}
	return cf.Entries, nil
}
