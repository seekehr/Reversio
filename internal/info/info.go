package info

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seekehr/reversio/internal/pe"
	"github.com/seekehr/reversio/internal/re_functions"
)

type Info struct {
	PE        *pe.PEInfo            `json:"pe,omitempty"`
	Functions *re_functions.Program `json:"functions,omitempty"`
}

func New() *Info {
	return &Info{}
}

func (i *Info) SetPE(peInfo *pe.PEInfo) {
	i.PE = peInfo
}

func (i *Info) SetFunctions(functions *re_functions.Program) {
	i.Functions = functions
}

func (i *Info) ToJSON() (string, error) {
	out, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(out), nil
}

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
