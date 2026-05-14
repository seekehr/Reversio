// Package re_functions handles decompilation of binary functions using Ghidra's
// headless analyzer. It invokes Ghidra with a custom script (ExportFunctions.java)
// that exports decompiled pseudocode, call graphs, and string references to JSON.
package re_functions

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// Program represents the full decompilation output for a binary, containing
// metadata and all recovered functions.
type Program struct {
	Program       string     `json:"program"`
	FunctionCount int        `json:"function_count"`
	Functions     []Function `json:"functions"`
}

// Function holds the decompiled representation of a single function, including
// its address, size, pseudocode, API imports it references, functions it calls,
// and string literals found within it.
type Function struct {
	Name       string   `json:"name"`
	Address    string   `json:"address"`
	Size       int      `json:"size"`
	Pseudocode string   `json:"pseudocode"`
	Imports    []string `json:"imports"`
	Calls      []string `json:"calls"`
	Strings    []string `json:"strings"`
}

// Load runs Ghidra's headless analyzer on the given executable. It imports the
// binary into a Ghidra project named "reversio" and executes ExportFunctions.java
// as a post-analysis script to produce the decompiled output.
//
// NOTE: This function is side-effect only - it writes output to disk (controlled by the
// Ghidra script) but does not return the path to the generated JSON. The caller must
// know the output location independently and call Parse() to read the results.
// Additionally, re-running with the same project will fail if the binary was already
// imported (Ghidra rejects duplicate imports without -overwrite).
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

// Parse reads and deserializes a previously exported functions JSON file
// (produced by Ghidra's ExportFunctions.java script) into a Program struct.
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