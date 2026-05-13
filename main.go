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
	"github.com/seekehr/reversio/internal/re_functions"
)

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env:", err)
		return
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
			if len(fields) >= 2 {
				reversio(fields[1])
			} else {
				fmt.Println("Second argument not found. Run r <executable_path>")
			}
		case "exit":
			fmt.Println("Exitting...")
		default:
			fmt.Println("Invalid command")
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error reading input:", err)
	}
}

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
	headlessPath := filepath.Join(os.Getenv("HEADLESS_GHIDRA_PATH"), "analyzeHeadless.bat")
	err = re_functions.Load(headlessPath, os.Getenv("GHIDRA_PROJECT_PATH"), os.Getenv("GHIDRA_SCRIPTS_PATH"), path)
	if err != nil {
		fmt.Println("Error loading functions:", err)
		return
	}
	fmt.Println("Functions loaded...")

	fileInfo := info.New()
	fileInfo.SetPE(peInfo)

	err = fileInfo.SaveInfo("./data")
	if err != nil {
		fmt.Println("Error saving info:", err)
		return
	}

	fmt.Println("Info saved to ./data folder.")
}
