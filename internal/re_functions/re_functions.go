package re_functions

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type Program struct {
	Program       string     `json:"program"`
	FunctionCount int        `json:"function_count"`
	Functions     []Function `json:"functions"`
}

type Function struct {
	Name       string   `json:"name"`
	Address    string   `json:"address"`
	Size       int      `json:"size"`
	Pseudocode string   `json:"pseudocode"`
	Imports    []string `json:"imports"`
	Calls      []string `json:"calls"`
	Strings    []string `json:"strings"`
}

func Load(headlessGhidraPath string, ghidraProjectPath string, ghidraScriptsPath string, executablePath string) error {
	cmd := exec.Command(headlessGhidraPath,
		ghidraProjectPath,
		"reversio",
		"-import", executablePath,
		"-scriptPath", ghidraScriptsPath,
		"-postScript", "ExportFunctions.java",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ghidra headless analysis failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func Parse(functionsJSONPath string) (*Program, error) {
	data, err := os.ReadFile(functionsJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read functions JSON: %w", err)
	}

	var program Program
	if err := json.Unmarshal(data, &program); err != nil {
		return nil, fmt.Errorf("failed to parse functions JSON: %w", err)
	}

	return &program, nil
}