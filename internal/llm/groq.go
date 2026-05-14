package llm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	groqChatURL  = "https://api.groq.com/openai/v1/chat/completions"
	DefaultModel = "llama-3.3-70b-versatile"
)

// Client holds credentials and configuration for the Groq chat API.
type Client struct {
	apiKey string
	Model  string
}

// Message represents a single chat message in the conversation.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

// NewClient creates a Groq client using the GROQ_API_KEY environment variable
// and the default model.
func NewClient() (*Client, error) {
	key := os.Getenv("GROQ_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("GROQ_API_KEY environment variable is not set")
	}
	return &Client{apiKey: key, Model: DefaultModel}, nil
}

// Chat sends a non-streaming chat completion request and returns the full
// response text.
func (c *Client) Chat(messages []Message) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:    c.Model,
		Messages: messages,
		Stream:   false,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, groqChatURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("groq request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return "", fmt.Errorf("groq returned %d: %s", resp.StatusCode, buf.String())
	}

	var result chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("groq returned no choices")
	}
	return result.Choices[0].Message.Content, nil
}

// ChatStream sends a streaming chat completion request. Each token is passed
// to onToken as it arrives via server-sent events. Blocks until the stream
// completes or an error occurs.
func (c *Client) ChatStream(messages []Message, onToken func(string)) error {
	body, err := json.Marshal(chatRequest{
		Model:    c.Model,
		Messages: messages,
		Stream:   true,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, groqChatURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("groq request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return fmt.Errorf("groq returned %d: %s", resp.StatusCode, buf.String())
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		var chunk streamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			onToken(chunk.Choices[0].Delta.Content)
		}
	}
	return scanner.Err()
}

