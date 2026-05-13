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

func (i *Info) SaveInfo(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	jsonStr, err := i.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "pe.json"), []byte(jsonStr), 0644)
}
