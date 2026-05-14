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
	"github.com/seekehr/reversio/internal/llm"
	"github.com/seekehr/reversio/internal/pe"
	"github.com/seekehr/reversio/internal/rag"
	"github.com/seekehr/reversio/internal/re_functions"
)

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env:", err)
		return
	}

	groqClient, err := llm.NewClient()
	if err != nil {
		fmt.Println("Warning: Groq client unavailable:", err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Reversio - Made by seekehr, powered by AI.")

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
			if len(fields) < 2 {
				fmt.Println("Usage: r <executable_path>")
				continue
			}
			if reversio(fields[1]) {
				queryMode(scanner, groqClient)
			}
		case "exit":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid command")
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
	}
}

// queryMode enters an interactive loop where the user can ask natural-language
// questions about the analyzed binary. Each query runs the full RAG pipeline
// (embed → search Qdrant → stream Groq response). Type "back" to return to
// the command prompt or "exit" to quit.
func queryMode(scanner *bufio.Scanner, client *llm.Client) {
	if client == nil {
		fmt.Println("Groq client is not configured. Set GROQ_API_KEY and restart.")
		return
	}

	fmt.Println("\n--- Query mode (ask anything about the binary, 'back' to return, 'exit' to quit) ---")

	for {
		fmt.Print("? ")
		if !scanner.Scan() {
			return
		}

		query := strings.TrimSpace(scanner.Text())
		if query == "" {
			continue
		}

		switch strings.ToLower(query) {
		case "back":
			fmt.Println("Returning to command mode.")
			return
		case "exit":
			fmt.Println("Exiting...")
			os.Exit(0)
		}

		err := client.Ask(query, func(token string) {
			fmt.Print(token)
		})
		if err != nil {
			fmt.Println("\nError:", err)
			continue
		}
		fmt.Println()
	}
}

// reversio runs the full analysis pipeline on a given PE executable and returns
// true if the binary was successfully analyzed and stored in Qdrant.
func reversio(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		fmt.Println("File does not exist at path:", path)
		return false
	}

	if !strings.HasSuffix(strings.ToLower(path), ".exe") {
		fmt.Println("File is not an .exe:", path)
		return false
	}
	fmt.Println("Found file...")
	fmt.Println("Parsing PE...")
	peInfo, err := pe.Parse(path)
	if err != nil {
		fmt.Println("Error parsing PE:", err)
		return false
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
		return false
	}
	fmt.Println("Functions loaded...")

	funcInfo, err := re_functions.Parse("./data/functions.json")
	if err != nil {
		fmt.Println("Error parsing functions JSON:", err)
		return false
	}

	fileInfo := info.New()
	fileInfo.SetPE(peInfo)
	fileInfo.SetFunctions(funcInfo)

	err = fileInfo.SaveInfo("./data")
	if err != nil {
		fmt.Println("Error saving info:", err)
		return false
	}

	fmt.Println("Info saved to ./data folder.")

	fmt.Println("Chunking...")
	chunks := rag.Chunker(fileInfo)
	fmt.Printf("Created %d chunks.\n", len(chunks))

	fmt.Println("Embedding chunks via Ollama (qwen3-embedding:4b)...")
	embedded, err := rag.Embed(chunks)
	if err != nil {
		fmt.Println("Error embedding chunks:", err)
		return false
	}
	fmt.Printf("Embedded %d chunks (dim=%d).\n", len(embedded), len(embedded[0].Embedding))

	fmt.Println("Storing in Qdrant...")
	if err := rag.Upsert(embedded); err != nil {
		fmt.Println("Error upserting to Qdrant:", err)
		return false
	}
	fmt.Printf("Stored %d vectors in Qdrant.\n", len(embedded))
	return true
}
