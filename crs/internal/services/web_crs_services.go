package services

import (
	"bytes"
	"context"
	"crs/internal/models"
	"crs/internal/telemetry"
	"encoding/json"
	"fmt"
	"go.opentelemetry.io/otel/attribute"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WebCRSService interface extends CRSService for web-specific operations
type WebCRSService interface {
	CRSService
	SubmitWebTask(task models.WebTask) error
	SubmitWebWorkerTask(task models.WebWorkerTask) error
	GetWebPOVStats(taskID string) (*models.WebPOVStatsResponse, error)
	ValidateTargetURL(url string) error
}

// Extend defaultCRSService with web-specific functionality
type webCRSServiceExtension struct {
	*defaultCRSService
	webTasksMutex    sync.RWMutex
	webTasks         map[string]*models.WebTaskDetail
	browserPoolMutex sync.Mutex
	activeBrowsers   int
	maxBrowsers      int
}

// NewWebCRSService creates a web-enabled CRS service
func NewWebCRSService(workerNodes int, workerBasePort int, model string) WebCRSService {
	baseService := NewCRSService(workerNodes, workerBasePort, model).(*defaultCRSService)

	maxBrowsers := 3 // Default: 3 concurrent browsers
	if envMax := os.Getenv("MAX_BROWSER_INSTANCES"); envMax != "" {
		// Parse envMax if needed
		maxBrowsers = 3
	}

	return &webCRSServiceExtension{
		defaultCRSService: baseService,
		webTasks:          make(map[string]*models.WebTaskDetail),
		maxBrowsers:       maxBrowsers,
	}
}

// SubmitWebTask submits a web fuzzing task
func (s *webCRSServiceExtension) SubmitWebTask(task models.WebTask) error {
	ctx, span := telemetry.StartSpan(context.Background(), "web.submit_task")
	defer span.End()

	span.SetAttributes(
		attribute.String("crs.task.message_id", task.MessageID.String()),
		attribute.Int("crs.task.count", len(task.Tasks)),
	)

	log.Printf("Received web fuzzing task with %d target(s)", len(task.Tasks))

	// Validate all target URLs
	for _, taskDetail := range task.Tasks {
		if err := s.ValidateTargetURL(taskDetail.TargetURL); err != nil {
			return fmt.Errorf("invalid target URL %s: %w", taskDetail.TargetURL, err)
		}
	}

	// Store web tasks
	s.webTasksMutex.Lock()
	for i := range task.Tasks {
		taskID := task.Tasks[i].TaskID.String()
		s.webTasks[taskID] = &task.Tasks[i]
	}
	s.webTasksMutex.Unlock()

	// Distribute to workers
	for _, taskDetail := range task.Tasks {
		workerTask := models.WebWorkerTask{
			MessageID:   task.MessageID,
			MessageTime: task.MessageTime,
			Tasks:       []models.WebTaskDetail{taskDetail},
			TargetURL:   taskDetail.TargetURL,
		}

		// Select worker based on target URL hash
		workerIndex := s.selectWorkerForURL(taskDetail.TargetURL)
		workerURL := fmt.Sprintf("http://localhost:%d/v1/web/task/", s.workerBasePort+workerIndex)

		go s.sendWebTaskToWorker(ctx, workerURL, workerTask)
	}

	return nil
}

// SubmitWebWorkerTask submits a web task to this specific worker
func (s *webCRSServiceExtension) SubmitWebWorkerTask(task models.WebWorkerTask) error {
	ctx, span := telemetry.StartSpan(context.Background(), "web.submit_worker_task")
	defer span.End()

	log.Printf("Worker processing web fuzzing task for URL: %s", task.TargetURL)

	for _, taskDetail := range task.Tasks {
		go s.executeWebFuzzingTask(ctx, taskDetail)
	}

	return nil
}

// executeWebFuzzingTask executes a web fuzzing task
func (s *webCRSServiceExtension) executeWebFuzzingTask(ctx context.Context, task models.WebTaskDetail) {
	span := telemetry.StartSpanFromContext(ctx, "web.execute_task")
	defer span.End()

	taskID := task.TaskID.String()

	span.SetAttributes(
		attribute.String("crs.task.id", taskID),
		attribute.String("crs.task.target_url", task.TargetURL),
		attribute.String("crs.task.framework", string(task.WebFramework)),
	)

	// Update task state
	s.updateTaskState(taskID, models.TaskStateRunning)

	// Acquire browser slot
	s.acquireBrowserSlot()
	defer s.releaseBrowserSlot()

	// Determine strategy (ws0_delta_new or wx0_delta_new)
	strategyScript := "ws0_delta_new.py"
	if task.Type == models.TaskTypeDelta {
		strategyScript = "wx0_delta_new.py" // Advanced multi-phase
	}

	// Build command
	strategyPath := filepath.Join("/crs/strategy/strategies", strategyScript)

	args := []string{
		strategyPath,
		task.TargetURL,
		task.ProjectName,
		task.Focus,
		"javascript", // Default language
		"--web-framework", string(task.WebFramework),
		"--browser-type", task.BrowserType,
		"--headless", fmt.Sprintf("%t", task.Headless),
		"--max-iterations", "5",
		"--fuzzing-timeout", "45",
		"--log-dir", filepath.Join(s.workDir, "logs"),
		"--pov-metadata-dir", s.povMetadataDir,
	}

	// Add vulnerability types
	if len(task.VulnerabilityTypes) > 0 {
		vulnTypes := make([]string, len(task.VulnerabilityTypes))
		for i, vt := range task.VulnerabilityTypes {
			vulnTypes[i] = string(vt)
		}
		args = append(args, "--vulnerability-types", strings.Join(vulnTypes, ","))
	}

	// Add POV phase for multi-phase strategies
	if task.POVPhase > 0 {
		args = append(args, "--pov-phase", fmt.Sprintf("%d", task.POVPhase))
	}

	// Execute strategy
	cmd := exec.CommandContext(ctx, "python3", args...)
	cmd.Dir = "/crs/strategy"

	// Set environment variables
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TASK_ID=%s", taskID),
		fmt.Sprintf("TARGET_URL=%s", task.TargetURL),
		fmt.Sprintf("WEB_FRAMEWORK=%s", task.WebFramework),
		fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
		fmt.Sprintf("WEB_ANALYSIS_SERVICE_URL=%s", os.Getenv("WEB_ANALYSIS_SERVICE_URL")),
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("Executing web fuzzing strategy: %s", strategyScript)
	err := cmd.Run()

	if err != nil {
		log.Printf("Web fuzzing task failed: %v\nStderr: %s", err, stderr.String())
		s.updateTaskState(taskID, models.TaskStateErrored)
		span.SetAttributes(attribute.String("crs.task.error", err.Error()))
	} else {
		log.Printf("Web fuzzing task completed successfully")
		s.updateTaskState(taskID, models.TaskStateSucceeded)
	}

	// Log output
	if stdout.Len() > 0 {
		log.Printf("Strategy output: %s", stdout.String())
	}
}

// selectWorkerForURL selects a worker based on URL hash (for load balancing)
func (s *webCRSServiceExtension) selectWorkerForURL(url string) int {
	// Simple hash-based selection
	hash := 0
	for _, c := range url {
		hash = (hash*31 + int(c)) % s.workerNodes
	}
	return hash
}

// acquireBrowserSlot blocks until a browser slot is available
func (s *webCRSServiceExtension) acquireBrowserSlot() {
	for {
		s.browserPoolMutex.Lock()
		if s.activeBrowsers < s.maxBrowsers {
			s.activeBrowsers++
			s.browserPoolMutex.Unlock()
			log.Printf("Browser slot acquired (%d/%d)", s.activeBrowsers, s.maxBrowsers)
			return
		}
		s.browserPoolMutex.Unlock()
		time.Sleep(5 * time.Second)
	}
}

// releaseBrowserSlot releases a browser slot
func (s *webCRSServiceExtension) releaseBrowserSlot() {
	s.browserPoolMutex.Lock()
	s.activeBrowsers--
	s.browserPoolMutex.Unlock()
	log.Printf("Browser slot released (%d/%d)", s.activeBrowsers, s.maxBrowsers)
}

// sendWebTaskToWorker sends a web task to a specific worker
func (s *webCRSServiceExtension) sendWebTaskToWorker(ctx context.Context, workerURL string, task models.WebWorkerTask) {
	span := telemetry.StartSpanFromContext(ctx, "web.send_to_worker")
	defer span.End()

	jsonData, err := json.Marshal(task)
	if err != nil {
		log.Printf("Failed to marshal web worker task: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", workerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create request to worker: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send web task to worker %s: %v", workerURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Worker returned non-200 status %d: %s", resp.StatusCode, string(body))
	}
}

// ValidateTargetURL validates a target URL
func (s *webCRSServiceExtension) ValidateTargetURL(url string) error {
	if url == "" {
		return fmt.Errorf("target URL cannot be empty")
	}

	// Basic URL validation
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("target URL must start with http:// or https://")
	}

	// TODO: Add more sophisticated validation
	// - DNS resolution check
	// - Port accessibility check
	// - SSL certificate validation (for https)

	return nil
}

// GetWebPOVStats retrieves statistics for web POVs
func (s *webCRSServiceExtension) GetWebPOVStats(taskID string) (*models.WebPOVStatsResponse, error) {
	// Read POV metadata directory
	povFiles, err := os.ReadDir(s.povMetadataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read POV directory: %w", err)
	}

	stats := &models.WebPOVStatsResponse{
		TaskID:              taskID,
		ByVulnerabilityType: make(map[models.WebVulnerabilityType]int),
		ByFramework:         make(map[models.WebFramework]int),
	}

	// Count POVs by type and framework
	for _, file := range povFiles {
		if !strings.HasPrefix(file.Name(), "web_pov_metadata_") {
			continue
		}

		// Read POV metadata
		povPath := filepath.Join(s.povMetadataDir, file.Name())
		data, err := os.ReadFile(povPath)
		if err != nil {
			continue
		}

		var pov models.WebPOVSubmission
		if err := json.Unmarshal(data, &pov); err != nil {
			continue
		}

		if pov.TaskID == taskID {
			stats.Count++
			stats.ByVulnerabilityType[pov.VulnerabilityType]++
			if pov.Framework != "" {
				stats.ByFramework[pov.Framework]++
			}
		}
	}

	return stats, nil
}

// updateTaskState updates the state of a task
func (s *webCRSServiceExtension) updateTaskState(taskID string, state models.TaskState) {
	s.tasksMutex.Lock()
	defer s.tasksMutex.Unlock()

	if task, exists := s.tasks[taskID]; exists {
		task.State = state
	}
}
