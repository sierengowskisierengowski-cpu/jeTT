package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	
)

// Configure the Two-Model Local Consensus Network
const (
	AnalyzerBrain  = "gemma2:2b"     // Google's code-syntax expert
	CommanderBrain = "granite3.3:2b" // IBM's security decision engine
)

type SecurityLog struct {
	PID            uint32 `json:"pid"`
	PPID           uint32 `json:"ppid"`
	UID            uint32 `json:"uid"`
	ParentProcess  string `json:"parent_process"`
	BinaryExecuted string `json:"binary_executed"`
}

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

// CleanAIResponse strips away intermediate reasoning/thinking tags from local models
func CleanAIResponse(rawResponse string) string {
	if strings.Contains(rawResponse, "</thought>") {
		parts := strings.Split(rawResponse, "</thought>")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return strings.TrimSpace(rawResponse)
}

// QueryOllama Engine speaks directly to your local loopback Ollama service
func QueryOllama(model string, prompt string) (string, error) {
	requestBody, err := json.Marshal(OllamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
	})
	if err != nil {
		return "", err
	}

	resp, err := http.Post("http://127.0.0.1:11434/api/generate", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", err
	}

	return CleanAIResponse(ollamaResp.Response), nil
}

// RunConsensusLoop routes telemetry through Gemma, then feeds the report into Granite
func RunConsensusLoop(secLog SecurityLog) {
	// --- PHASE 1: GEMMA 2 2B TECHNICAL DECONSTRUCTION ---
	gemmaPrompt := fmt.Sprintf(
		"You are a neutral code analyzer. Describe strictly what this execution context does without judging if it is malicious or safe.\n"+
			"Parent Process: %s\nExecuted Command: %s\nUser Context ID: %d\nProvide a technical summary in one sentence:",
		secLog.ParentProcess, secLog.BinaryExecuted, secLog.UID,
	)

	gemmaReport, err := QueryOllama(AnalyzerBrain, gemmaPrompt)
	if err != nil {
		log.Printf("[!] Phase 1 (Gemma) Failed: %v", err)
		return
	}
	fmt.Printf("\n[🔬 GEMMA ANALYSIS]: %s\n", gemmaReport)

	// --- PHASE 2: GRANITE 3.3 2B SECURITY COMMAND VERDICT ---
	granitePrompt := fmt.Sprintf(
		"You are Cerberus-Commander, an automated endpoint defense coordinator. Read this system event profile and the technical analysis report.\n\n"+
			"Event Profile:\n- Binary Path: %s\n- User ID: %d\n\nTechnical Analysis:\n%s\n\n"+
			"Determine if this is a hostile attack or unauthorized privilege escalation. You must end your response with exactly 'VERDICT: KILL' or 'VERDICT: ALLOW':",
		secLog.BinaryExecuted, secLog.UID, gemmaReport,
	)

	graniteVerdict, err := QueryOllama(CommanderBrain, granitePrompt)
	if err != nil {
		log.Printf("[!] Phase 2 (Granite) Failed: %v", err)
		return
	}
	fmt.Printf("[⚔️ GRANITE COMMAND]: %s\n\n", graniteVerdict)
}

func main() {
	log.Println("[+] Cerberus Command Tower (Right Head) waking up...")
	log.Println("[+] Multi-Model Consensus Engine initialized on port 8080...")

	http.HandleFunc("/telemetry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
			return
		}

		var secLog SecurityLog
		if err := json.NewDecoder(r.Body).Decode(&secLog); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Process the consensus reasoning asynchronously so your kernel data loop never pauses
		go RunConsensusLoop(secLog)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"received"}`))
	})

	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatalf("[!] Command Tower network pipeline dropped: %v", err)
	}
}
