package models

import (
	"github.com/google/uuid"
)

// Web fuzzing specific task types
type WebTaskType string

const (
	WebTaskTypeBasic    WebTaskType = "web-basic"    // WS0 strategy
	WebTaskTypeAdvanced WebTaskType = "web-advanced" // WX0 strategy with multi-phase
)

// Web vulnerability types
type WebVulnerabilityType string

const (
	WebVulnXSS                WebVulnerabilityType = "xss"
	WebVulnSQLi               WebVulnerabilityType = "sqli"
	WebVulnCSRF               WebVulnerabilityType = "csrf"
	WebVulnPrototypePollution WebVulnerabilityType = "prototype_pollution"
	WebVulnXXE                WebVulnerabilityType = "xxe"
	WebVulnSSRF               WebVulnerabilityType = "ssrf"
	WebVulnOpenRedirect       WebVulnerabilityType = "open_redirect"
	WebVulnPathTraversal      WebVulnerabilityType = "path_traversal"
	WebVulnCodeInjection      WebVulnerabilityType = "code_injection"
)

// Web framework types
type WebFramework string

const (
	WebFrameworkReact   WebFramework = "react"
	WebFrameworkVue     WebFramework = "vue"
	WebFrameworkAngular WebFramework = "angular"
	WebFrameworkExpress WebFramework = "express"
	WebFrameworkNextJS  WebFramework = "nextjs"
	WebFrameworkUnknown WebFramework = "unknown"
)

// WebTaskDetail extends TaskDetail for web-specific fuzzing
type WebTaskDetail struct {
	TaskDetail
	TargetURL           string                 `json:"target_url"`           // Required: Target web application URL
	WebFramework        WebFramework           `json:"web_framework"`        // Detected or specified framework
	VulnerabilityTypes  []WebVulnerabilityType `json:"vulnerability_types"`  // Types to test for
	BrowserType         string                 `json:"browser_type"`         // chromium, firefox, webkit
	Headless            bool                   `json:"headless"`             // Run browser in headless mode
	POVPhase            int                    `json:"pov_phase"`            // For multi-phase strategies (0-3)
	MaxBrowserInstances int                    `json:"max_browser_instances"` // Limit concurrent browsers
	CaptureScreenshots  bool                   `json:"capture_screenshots"`  // Save screenshots on success
}

// WebPOVSubmission represents a web vulnerability submission
type WebPOVSubmission struct {
	TaskID             string               `json:"task_id"`
	POVID              string               `json:"pov_id,omitempty"`
	TargetURL          string               `json:"target_url"`
	VulnerabilityType  WebVulnerabilityType `json:"vulnerability_type"`
	Engine             string               `json:"engine"` // "playwright"
	Framework          WebFramework         `json:"framework,omitempty"`
	PayloadFile        string               `json:"payload_file"`        // Base64 encoded payload
	TestOutput         string               `json:"test_output"`         // Browser/HTTP test output
	Signature          string               `json:"signature"`           // Vulnerability signature hash
	Evidence           *WebPOVEvidence      `json:"evidence,omitempty"`  // Evidence package
	Strategy           string               `json:"strategy"`            // ws0_delta, wx0_delta
	StrategyVersion    string               `json:"strategy_version"`
	POVPhase           int                  `json:"pov_phase,omitempty"` // For multi-phase
}

// WebPOVEvidence contains proof of vulnerability
type WebPOVEvidence struct {
	Screenshot    string   `json:"screenshot,omitempty"`     // Base64 encoded PNG
	HAR           string   `json:"har,omitempty"`            // HAR file content
	DOMSnapshot   string   `json:"dom_snapshot,omitempty"`   // HTML DOM snapshot
	ConsoleLogs   []string `json:"console_logs,omitempty"`   // Browser console logs
	NetworkErrors []string `json:"network_errors,omitempty"` // Network errors
}

// WebTask represents a web fuzzing task
type WebTask struct {
	MessageID   uuid.UUID       `json:"message_id"`
	MessageTime int64           `json:"message_time"`
	Tasks       []WebTaskDetail `json:"tasks"`
}

// WebWorkerTask represents a web fuzzing task for a specific worker
type WebWorkerTask struct {
	MessageID   uuid.UUID       `json:"message_id"`
	MessageTime int64           `json:"message_time"`
	Tasks       []WebTaskDetail `json:"tasks"`
	TargetURL   string          `json:"target_url"` // The specific target URL this worker should test
}

// WebTaskValidPOVsResponse represents web POVs for a task
type WebTaskValidPOVsResponse struct {
	TaskID string             `json:"task_id"`
	POVs   []WebPOVSubmission `json:"povs"`
	Count  int                `json:"count"`
}

// WebPOVSubmissionResponse represents the response from submitting a web POV
type WebPOVSubmissionResponse struct {
	Status string `json:"status"`
	POVID  string `json:"pov_id"`
	TaskID string `json:"task_id"`
}

// WebPOVStatsResponse represents statistics for web POVs
type WebPOVStatsResponse struct {
	TaskID              string                          `json:"task_id"`
	Count               int                             `json:"count"`
	ByVulnerabilityType map[WebVulnerabilityType]int    `json:"by_vulnerability_type"`
	ByFramework         map[WebFramework]int            `json:"by_framework"`
}
