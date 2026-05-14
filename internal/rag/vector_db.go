package rag

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

const collectionName = "reversio"

func qdrantURL() string {
	if host := os.Getenv("QDRANT_HOST"); host != "" {
		return host
	}
	return "http://localhost:6333"
}

// SearchResult holds a single Qdrant search hit with its payload and score.
type SearchResult struct {
	ChunkID string
	Type    string
	Content string
	Score   float64
}

type searchResponse struct {
	Result []struct {
		Score   float64        `json:"score"`
		Payload map[string]any `json:"payload"`
	} `json:"result"`
}

// Search finds the topK nearest chunks to queryVector in Qdrant.
func Search(queryVector []float64, topK int) ([]SearchResult, error) {
	body, err := json.Marshal(map[string]any{
		"vector":       queryVector,
		"limit":        topK,
		"with_payload": true,
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(
		fmt.Sprintf("%s/collections/%s/points/search", qdrantURL(), collectionName),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("qdrant request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("qdrant returned %d: %s", resp.StatusCode, buf.String())
	}

	var sr searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decoding search response: %w", err)
	}

	results := make([]SearchResult, len(sr.Result))
	for i, hit := range sr.Result {
		results[i] = SearchResult{
			Score: hit.Score,
		}
		if v, ok := hit.Payload["chunk_id"].(string); ok {
			results[i].ChunkID = v
		}
		if v, ok := hit.Payload["type"].(string); ok {
			results[i].Type = v
		}
		if v, ok := hit.Payload["content"].(string); ok {
			results[i].Content = v
		}
	}
	return results, nil
}

// Upsert recreates the Qdrant collection and inserts all embedded chunks,
// destroying any previously stored data in the collection.
func Upsert(embedded []EmbeddedChunk) error {
	if len(embedded) == 0 {
		return nil
	}

	dim := len(embedded[0].Embedding)

	if err := deleteCollection(); err != nil {
		return fmt.Errorf("deleting collection: %w", err)
	}

	if err := createCollection(dim); err != nil {
		return fmt.Errorf("creating collection: %w", err)
	}

	for start := 0; start < len(embedded); start += batchSize {
		end := start + batchSize
		if end > len(embedded) {
			end = len(embedded)
		}
		if err := upsertBatch(embedded[start:end], start); err != nil {
			return fmt.Errorf("upserting batch %d–%d: %w", start, end-1, err)
		}
	}

	return nil
}

func deleteCollection() error {
	req, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/collections/%s", qdrantURL(), collectionName), nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("qdrant request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return fmt.Errorf("qdrant returned %d: %s", resp.StatusCode, buf.String())
	}
	return nil
}

func createCollection(dim int) error {
	body, err := json.Marshal(map[string]any{
		"vectors": map[string]any{
			"size":     dim,
			"distance": "Cosine",
		},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut,
		fmt.Sprintf("%s/collections/%s", qdrantURL(), collectionName), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("qdrant request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return fmt.Errorf("qdrant returned %d: %s", resp.StatusCode, buf.String())
	}
	return nil
}

type qdrantPoint struct {
	ID      int            `json:"id"`
	Vector  []float64      `json:"vector"`
	Payload map[string]any `json:"payload"`
}

func upsertBatch(batch []EmbeddedChunk, offset int) error {
	points := make([]qdrantPoint, len(batch))
	for i, ec := range batch {
		points[i] = qdrantPoint{
			ID:     offset + i,
			Vector: ec.Embedding,
			Payload: map[string]any{
				"chunk_id": ec.Chunk.ID,
				"type":     ec.Chunk.Type,
				"content":  ec.Chunk.Content,
			},
		}
	}

	body, err := json.Marshal(map[string]any{"points": points})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut,
		fmt.Sprintf("%s/collections/%s/points", qdrantURL(), collectionName), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("qdrant request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return fmt.Errorf("qdrant returned %d: %s", resp.StatusCode, buf.String())
	}
	return nil
}
