package llm

import (
	"context"
	"errors"
	"os"

	"github.com/sashabaranov/go-openai"
)

var client *openai.Client

func init() {
	openaiToken := os.Getenv("OPENAI_API_KEY")
	if openaiToken != "" {
		client = openai.NewClient(openaiToken)
	}
}

func Query(prompt string) (string, error) {
	if client == nil {
		return "", errors.New("no token defined")
	}

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT3Dot5Turbo,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)
	if err != nil {
		return "", err
	}

	if len(resp.Choices) == 0 {
		return "", errors.New("no data")
	}

	data := resp.Choices[0].Message.Content

	return data, nil
}
