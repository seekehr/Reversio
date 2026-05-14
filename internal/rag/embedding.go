package rag

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

const (
	embeddingModel = "qwen3-embedding:4b"
	batchSize      = 64
)

func ollamaEmbedURL() string {
	if host := os.Getenv("OLLAMA_HOST"); host != "" {
		return host + "/api/embed"
	}
	return "http://localhost:11434/api/embed"
}

// EmbeddedChunk pairs a Chunk with its float64 embedding vector.
type EmbeddedChunk struct {
	Chunk
	Embedding []float64
}

type embedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embedResponse struct {
	Embeddings [][]float64 `json:"embeddings"`
}

// Embed sends chunk contents to the Ollama embedding API and returns
// EmbeddedChunks with their corresponding vectors. Chunks are batched
// to avoid oversized requests.
func Embed(chunks []Chunk) ([]EmbeddedChunk, error) {
	if len(chunks) == 0 {
		return nil, nil
	}

	embedded := make([]EmbeddedChunk, 0, len(chunks))

	for start := 0; start < len(chunks); start += batchSize {
		end := start + batchSize
		if end > len(chunks) {
			end = len(chunks)
		}
		batch := chunks[start:end]

		texts := make([]string, len(batch))
		for i, c := range batch {
			texts[i] = c.Content
		}

		vectors, err := callOllamaEmbed(texts)
		if err != nil {
			return nil, fmt.Errorf("embedding batch %d-%d: %w", start, end-1, err)
		}
		if len(vectors) != len(batch) {
			return nil, fmt.Errorf("expected %d embeddings, got %d", len(batch), len(vectors))
		}

		for i, c := range batch {
			embedded = append(embedded, EmbeddedChunk{
				Chunk:     c,
				Embedding: vectors[i],
			})
		}
	}

	return embedded, nil
}

func callOllamaEmbed(texts []string) ([][]float64, error) {
	body, err := json.Marshal(embedRequest{
		Model: embeddingModel,
		Input: texts,
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(ollamaEmbedURL(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("ollama returned %d: %s", resp.StatusCode, buf.String())
	}

	var result embedResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return result.Embeddings, nil
}
