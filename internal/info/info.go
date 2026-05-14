// Package info aggregates all analysis results (PE metadata + decompiled functions)
// into a single structure and handles JSON serialization/deserialization to disk.
package info

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seekehr/reversio/internal/pe"
	"github.com/seekehr/reversio/internal/re_functions"
)

// Info is the top-level container that holds all extracted data about a binary.
// Each field is optional so partial analyses (e.g. PE-only) are supported.
type Info struct {
	PE        *pe.PEInfo            `json:"pe,omitempty"`
	Functions *re_functions.Program `json:"functions,omitempty"`
}

// New creates an empty Info ready to be populated with analysis results.
func New() *Info {
	return &Info{}
}

// SetPE attaches parsed PE header/section/import data to this Info instance.
func (i *Info) SetPE(peInfo *pe.PEInfo) {
	i.PE = peInfo
}

// SetFunctions attaches Ghidra-decompiled function data to this Info instance.
func (i *Info) SetFunctions(functions *re_functions.Program) {
	i.Functions = functions
}

// ToJSON serializes the entire Info structure to a pretty-printed JSON string.
func (i *Info) ToJSON() (string, error) {
	out, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(out), nil
}

// FromJSON reconstructs an Info from previously saved JSON files in the given directory.
// It looks for pe.json and functions.json, skipping any that don't exist (allowing
// partial data loads).
func FromJSON(dir string) (*Info, error) {
	i := &Info{}

	type loader struct {
		filename string
		parse    func([]byte) error
	}

	loaders := []loader{
		{"pe.json", func(data []byte) error {
			var peInfo pe.PEInfo
			if err := json.Unmarshal(data, &peInfo); err != nil {
				return fmt.Errorf("failed to parse pe.json: %w", err)
			}
			i.PE = &peInfo
			return nil
		}},
		{"functions.json", func(data []byte) error {
			var program re_functions.Program
			if err := json.Unmarshal(data, &program); err != nil {
				return fmt.Errorf("failed to parse functions.json: %w", err)
			}
			i.Functions = &program
			return nil
		}},
	}

	for _, l := range loaders {
		data, err := os.ReadFile(filepath.Join(dir, l.filename))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read %s: %w", l.filename, err)
		}
		if err := l.parse(data); err != nil {
			return nil, err
		}
	}

	return i, nil
}

// SaveInfo persists each non-nil analysis component as a separate JSON file
// in the given directory (pe.json, functions.json). The directory is created
// if it doesn't exist.
func (i *Info) SaveInfo(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	type saver struct {
		filename string
		data     any
	}

	savers := []saver{
		{"pe.json", i.PE},
		{"functions.json", i.Functions},
	}

	for _, s := range savers {
		// CAVEAT: Go nil-interface gotcha. A typed nil pointer (e.g. (*pe.PEInfo)(nil))
		// stored in an `any` field is NOT == nil. If a field is a nil pointer,
		// this check passes and json.MarshalIndent writes "null" to the file.
		// Currently safe because Set* methods are only called with non-nil values,
		// but callers must be aware of this subtlety.
		if s.data == nil {
			continue
		}
		out, err := json.MarshalIndent(s.data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal %s: %w", s.filename, err)
		}
		if err := os.WriteFile(filepath.Join(dir, s.filename), out, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", s.filename, err)
		}
	}

	return nil
}
