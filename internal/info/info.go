package info

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seekehr/reversio/internal/pe"
)

type Info struct {
	PE *pe.PEInfo `json:"pe,omitempty"`
}

func New() *Info {
	return &Info{}
}

func (i *Info) SetPE(peInfo *pe.PEInfo) {
	i.PE = peInfo
}

func (i *Info) ToJSON() (string, error) {
	out, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(out), nil
}

func (i *Info) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}
	jsonStr, err := i.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return os.WriteFile(path, []byte(jsonStr), 0644)
}
