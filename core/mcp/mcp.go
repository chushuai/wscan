/*
*
2 * @Author: shaochuyu
3 * @Date: 8/24/25
4
*/
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"wscan/core/entry"
	"wscan/core/reverse"

	logger "wscan/core/utils/log"

	"github.com/urfave/cli/v2"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// JSON Schema 定义
var createTaskSchema = &jsonschema.Schema{
	Type: "object",
	Properties: map[string]*jsonschema.Schema{
		"name": {Type: "string"},
		"scan_url": {
			Type:        "string",
			Description: "Target URL to scan; must start with http:// or https://",
		},
		"crawler_type": {
			Type:        "string",
			Enum:        []interface{}{"url", "basic", "browser"},
			Description: "Type of crawler to use: 'url' (simple URL fetch), 'basic' (default, lightweight HTML parsing), or 'browser' (full browser emulation with JavaScript support)",
		},
	},
	Required: []string{"name", "scan_url"},
}

type createTaskParams struct {
	Name        string `json:"name"`
	ScanUrl     string `json:"scan_url"`
	CrawlerType string `json:"crawler_type"`
}

var taskIdSchema = &jsonschema.Schema{
	Type: "object",
	Properties: map[string]*jsonschema.Schema{
		"id": {Type: "string"},
	},
	Required: []string{"id"},
}

type taskIdParams struct {
	ID string `json:"id"`
}

var controlTaskSchema = &jsonschema.Schema{
	Type: "object",
	Properties: map[string]*jsonschema.Schema{
		"id": {
			Type: "string",
		},
		"action": {
			Type: "string",
			Enum: []any{"start", "pause", "stop", "delete"},
		},
	},
	Required: []string{"id", "action"},
}

type controlTaskParams struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

type getTaskResultParams struct {
	ID    string `json:"id"`
	Start int    `json:"start"`
	Size  int    `json:"size"`
}

// Define input schema with pagination
var getTaskResultSchema = &jsonschema.Schema{
	Type: "object",
	Properties: map[string]*jsonschema.Schema{
		"id": {
			Type:        "string",
			Description: "Unique identifier of the task",
		},
		"start": {
			Type:        "integer",
			Description: "Result offset (0-based). Default: 0",
		},
		"size": {
			Type:        "integer",
			Description: "Number of items to return. Default: 1, Since the data volume may be large, it is not recommended to change the size value.",
		},
	},
	Required: []string{"id", "start", "size"},
}

var taskManager = NewTaskManager()

func CreateTask(ctx context.Context, req *mcp.CallToolRequest, args createTaskParams) (*mcp.CallToolResult, any, error) {
	if args.CrawlerType == "" {
		args.CrawlerType = "basic"
	}
	task := taskManager.CreateTask(args.Name, args.ScanUrl, func(t *Task) error {
		return UrlScan(t, args.CrawlerType)
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Task created. Task ID=" + task.ID},
		}}, nil, nil
}

func ControlTask(ctx context.Context, req *mcp.CallToolRequest, args controlTaskParams) (*mcp.CallToolResult, any, error) {
	task, exists := taskManager.GetTask(args.ID)
	if !exists {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Task not found: " + args.ID},
			}}, nil, nil
	}

	switch args.Action {
	case "start":
		if err := task.Start(); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: err.Error() + ": " + args.ID},
				}}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Task started: " + args.ID},
			}}, nil, nil

	case "pause":
		if err := task.Pause(); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: err.Error() + ": " + args.ID},
				}}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Task paused: " + args.ID},
			}}, nil, nil
	case "stop":
		if err := task.Stop(); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: err.Error() + ": " + args.ID},
				}}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Task stopped: " + args.ID},
			}}, nil, nil

	case "delete":
		if err := taskManager.DeleteTask(args.ID); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: err.Error() + ": " + args.ID},
				}}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Task deleted: " + args.ID},
			}}, nil, nil

	default:
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Unsupported action: " + args.Action},
			}}, nil, nil
	}
}

func GetTaskStatus(ctx context.Context, req *mcp.CallToolRequest, args taskIdParams) (*mcp.CallToolResult, any, error) {
	task, exists := taskManager.GetTask(args.ID)
	if !exists {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Task not found: %s", args.ID)},
			},
		}, nil, nil
	}

	status := task.GetStatus() // Assuming your Task struct has a GetStatus() method

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: fmt.Sprintf(`Task status:
ID: %s
Name: %s
Status: %s`, task.ID, task.Name, status),
			},
		},
	}, nil, nil
}

func GetTaskResult(ctx context.Context, req *mcp.CallToolRequest, args getTaskResultParams) (*mcp.CallToolResult, any, error) {
	task, exists := taskManager.GetTask(args.ID)
	if !exists {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("任务ID: %s不存在", args.ID)},
			}}, nil, nil
	}
	result, err := task.GetResult()
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: err.Error() + args.ID},
			}}, nil, nil
	}
	total := len(result.Output)
	start := args.Start
	size := args.Size
	if size == 0 {
		size = 1
	}
	end := start + size
	if end > total {
		end = total
	}
	if start >= total {
		start = total - 1
	}
	slice := result.Output[start:end]
	results := make([]interface{}, len(slice))
	for i, v := range slice {
		results[i] = v
	}
	// 构造带分页信息的响应（推荐）
	response := map[string]interface{}{
		"start": start,
		"size":  size,
		"total": total,
		"data":  results,
	}
	data, err := json.Marshal(response)
	if err != nil {
		logger.Error("marshal result failed", "error", err)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "internal error: failed to format response"},
			},
		}, nil, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil

}

var globalConfig *entry.CliEntryConfig
var globalReverse *reverse.Reverse

func StartMcpServer(c *cli.Context) {
	var err error
	addr := fmt.Sprintf("%s:%d", c.String("mcp-host"), c.Int("mcp-port"))
	server := mcp.NewServer(&mcp.Implementation{Name: "Website Security Inspection Tool"}, nil)
	globalConfig, err = entry.LoadOrGenConfig(c)
	if err != nil {
		logger.Fatal(err)
	}
	if c.Bool("dump-config") == true {
		logger.Info("Dumping example config to ./config.yaml.example")
	}
	globalReverse = reverse.NewReverse(globalConfig.Reverse)
	// Tool 1: Create task
	mcp.AddTool(server, &mcp.Tool{
		Name:        "create_task",
		Description: "Create a new task",
		InputSchema: createTaskSchema,
	}, CreateTask)

	// Tool 2: Control task
	mcp.AddTool(server, &mcp.Tool{
		Name:        "control_task",
		Description: "Control a task: supports start, pause, stop, and delete operations",
		InputSchema: controlTaskSchema,
	}, ControlTask)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_task_status",
		Description: "Get the current status of a task, such as created, running, paused, stopped, failed, finished, etc.",
		InputSchema: taskIdSchema,
	}, GetTaskStatus)

	// Tool 6: View task results
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_task_result",
		Description: "Retrieve a paginated segment of the task execution result using start and size",
		InputSchema: getTaskResultSchema,
	}, GetTaskResult)

	logger.Printf("MCP server serving at %s", addr)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil)

	logger.Fatal(http.ListenAndServe(addr, handler))
}
