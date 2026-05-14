// Reversio is a reverse engineering assistant that parses Windows PE executables,
// extracts function information via Ghidra headless analysis, and prepares the data
// for AI-powered analysis through RAG (Retrieval-Augmented Generation) chunking.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/seekehr/reversio/internal/info"
	"github.com/seekehr/reversio/internal/pe"
	"github.com/seekehr/reversio/internal/rag"
	"github.com/seekehr/reversio/internal/re_functions"
)

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env:", err)
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Reversio - Made by seekehr, powered by AI.")

	// Interactive REPL loop
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		cmd := strings.ToLower(fields[0])

		switch cmd {
		case "reversio", "r", "reverse":
			if len(fields) >= 2 {
				reversio(fields[1])
			} else {
				fmt.Println("Second argument not found. Run r <executable_path>")
			}
		case "exit":
			// BUG: This prints but does NOT break out of the loop or call os.Exit.
			// The REPL continues running after printing. Needs a `return` or `os.Exit(0)`.
			fmt.Println("Exitting...")
		default:
			fmt.Println("Invalid command")
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
	}
}

// reversio runs the full analysis pipeline on a given PE executable:
// 1. Validates the file exists and is a .exe
// 2. Parses PE headers, sections, imports, exports, resources, and TLS callbacks
// 3. Invokes Ghidra headless analysis to decompile functions
// 4. Saves all extracted information as JSON to the ./data folder
func reversio(path string) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		fmt.Println("File does not exist at path:", path)
		return
	}

	if !strings.HasSuffix(strings.ToLower(path), ".exe") {
		fmt.Println("File is not an .exe:", path)
		return
	}
	fmt.Println("Found file...")
	fmt.Println("Parsing PE...")
	peInfo, err := pe.Parse(path)
	if err != nil {
		fmt.Println("Error parsing PE:", err)
		return
	}

	fmt.Println("Parsing functions...")
	headlessScript := "analyzeHeadless.bat"
	if _, err := os.Stat(filepath.Join(os.Getenv("HEADLESS_GHIDRA_PATH"), headlessScript)); err != nil {
		headlessScript = "analyzeHeadless"
	}
	headlessPath := filepath.Join(os.Getenv("HEADLESS_GHIDRA_PATH"), headlessScript)
	err = re_functions.Load(headlessPath, os.Getenv("GHIDRA_PROJECT_PATH"), os.Getenv("GHIDRA_SCRIPTS_PATH"), path)
	if err != nil {
		fmt.Println("Error loading functions:", err)
		return
	}
	fmt.Println("Functions loaded...")

	funcInfo, err := re_functions.Parse("./data/functions.json")
	if err != nil {
		fmt.Println("Error parsing functions JSON:", err)
		return
	}

	fileInfo := info.New()
	fileInfo.SetPE(peInfo)
	fileInfo.SetFunctions(funcInfo)

	err = fileInfo.SaveInfo("./data")
	if err != nil {
		fmt.Println("Error saving info:", err)
		return
	}

	fmt.Println("Info saved to ./data folder.")

	fmt.Println("Chunking...")
	chunks := rag.Chunker(fileInfo)
	fmt.Printf("Created %d chunks.\n", len(chunks))

	fmt.Println("Embedding chunks via Ollama (qwen3-embedding:4b)...")
	embedded, err := rag.Embed(chunks)
	if err != nil {
		fmt.Println("Error embedding chunks:", err)
		return
	}
	fmt.Printf("Embedded %d chunks (dim=%d).\n", len(embedded), len(embedded[0].Embedding))
}
