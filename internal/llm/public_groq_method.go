package llm

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/seekehr/reversio/internal/rag"
)

const promptPath = "resources/ghidra_scripts/prompt.txt"

var (
	promptOnce         sync.Once
	cachedSystemPrompt string
	promptLoadErr      error
)

func loadSystemPrompt() (string, error) {
	promptOnce.Do(func() {
		data, err := os.ReadFile(promptPath)
		if err != nil {
			promptLoadErr = fmt.Errorf("loading prompt template: %w", err)
			return
		}

		raw := string(data)
		const sysPrefix = "SYSTEM:\n"
		const userMarker = "\nUSER QUESTION:"

		sysStart := strings.Index(raw, sysPrefix)
		userStart := strings.Index(raw, userMarker)
		if sysStart == -1 || userStart == -1 {
			promptLoadErr = fmt.Errorf("prompt.txt missing SYSTEM or USER QUESTION markers")
			return
		}
		cachedSystemPrompt = strings.TrimSpace(raw[sysStart+len(sysPrefix) : userStart])
	})
	return cachedSystemPrompt, promptLoadErr
}

// Query builds a RAG-augmented prompt from the user's question and pre-fetched
// context chunks, then streams the Groq response token-by-token via onToken.
// The system prompt is loaded from resources/ghidra_scripts/prompt.txt (cached
// after the first call).
func (c *Client) Query(query string, contextChunks []string, onToken func(string)) error {
	sysPrompt, err := loadSystemPrompt()
	if err != nil {
		return err
	}

	var userContent strings.Builder
	userContent.WriteString("USER QUESTION:\n")
	userContent.WriteString(query)
	userContent.WriteString("\n\nRETRIEVED FUNCTION CONTEXT:\n")
	for _, chunk := range contextChunks {
		userContent.WriteString(chunk)
		userContent.WriteString("\n---\n")
	}

	messages := []Message{
		{Role: "system", Content: sysPrompt},
		{Role: "user", Content: userContent.String()},
	}
	return c.ChatStream(messages, onToken)
}

// Ask runs the full RAG pipeline for a natural-language question:
//  1. Embeds the query via Ollama
//  2. Searches Qdrant for the top 20 most similar chunks
//  3. Streams the Groq LLM response via onToken
func (c *Client) Ask(query string, onToken func(string)) error {
	vec, err := rag.EmbedQuery(query)
	if err != nil {
		return fmt.Errorf("embedding query: %w", err)
	}

	results, err := rag.Search(vec, 20)
	if err != nil {
		return fmt.Errorf("searching vectors: %w", err)
	}

	chunks := make([]string, len(results))
	for i, r := range results {
		chunks[i] = r.Content
	}

	return c.Query(query, chunks, onToken)
}
