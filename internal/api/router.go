
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/farajialireza/inputguard/internal/sanitize"
	"github.com/gorilla/mux"
)

const maxRequestBody = 1 << 20 // 1 MB

type APIResponse struct {
	Valid bool   `json:"valid"`
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

type TextRequest struct {
	Value            string `json:"value"`
	MaxLen           int    `json:"max_len"`
	KeepFormatting   bool   `json:"keep_formatting"`
}

type LabelRequest struct {
	Value string `json:"value"`
}

type AppNameRequest struct {
	Value     string   `json:"value"`
	Allowlist []string `json:"allowlist,omitempty"`
}

type AbsolutePathRequest struct {
	Value        string   `json:"value"`
	AllowedRoots []string `json:"allowed_roots,omitempty"`
}

type RelativePathRequest struct {
	Value   string `json:"value"`
	MaxLen  int    `json:"max_len"`
	AllowDot bool  `json:"allow_dot"`
}

type OpenerCommandRequest struct {
	Value string `json:"value"`
}

// NewRouter creates and configures the API router.
func NewRouter() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/v1/validate/text", validateText).Methods(http.MethodPost)
	r.HandleFunc("/v1/validate/label", validateLabel).Methods(http.MethodPost)
	r.HandleFunc("/v1/validate/app-name", validateAppName).Methods(http.MethodPost)
	r.HandleFunc("/v1/validate/absolute-path", validateAbsolutePath).Methods(http.MethodPost)
	r.HandleFunc("/v1/validate/relative-path", validateRelativePath).Methods(http.MethodPost)
	r.HandleFunc("/v1/validate/opener-command", validateOpenerCommand).Methods(http.MethodPost)

	return r
}

// decodeRequest decodes and validates a JSON request body.
func decodeRequest(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain a single JSON object")
	}

	return nil
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, response APIResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

// respond handles validation results.
func respond(w http.ResponseWriter, value string, err error) {
	if err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Valid: true,
		Value: value,
	})
}

func validateText(w http.ResponseWriter, r *http.Request) {
	var req TextRequest

	if err := decodeRequest(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Error: "invalid request: " + err.Error()})
		return
	}

	maxLen := req.MaxLen
	if maxLen == 0 {
		maxLen = sanitize.MaxGenericLen
	}

	value, err := sanitize.SanitizeText(req.Value, maxLen, req.KeepFormatting)
	respond(w, value, err)
}

func validateLabel(w http.ResponseWriter, r *http.Request) {
	var req LabelRequest

	if err := decodeRequest(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Error: "invalid request: " + err.Error()})
		return
	}

	value, err := sanitize.SanitizeLabel(req.Value)
	respond(w, value, err)
}

func validateAppName(w http.ResponseWriter, r *http.Request) {
	var req AppNameRequest

	if err := decodeRequest(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Error: "invalid request: " + err.Error()})
		return
	}

	allowlist := make(map[string]struct{}, len(req.Allowlist))
	for _, name := range req.Allowlist {
		allowlist[strings.ToLower(name)] = struct{}{}
	}

	value, err := sanitize.SanitizeAppName(req.Value, allowlist)
	respond(w, value, err)
}

func validateAbsolutePath(w http.ResponseWriter, r *http.Request) {
	var req AbsolutePathRequest

	if err := decodeRequest(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Error: "invalid request: " + err.Error()})
		return
	}

	value, err := sanitize.SanitizeAbsolutePath(req.Value, req.AllowedRoots)
	respond(w, value, err)
}

func validateRelativePath(w http.ResponseWriter, r *http.Request) {
	var req RelativePathRequest

	if err := decodeRequest(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Error: "invalid request: " + err.Error()})
		return
	}

	maxLen := req.MaxLen
	if maxLen == 0 {
		maxLen = sanitize.MaxPathLen
	}

	value, err := sanitize.SanitizeSafeRelativePath(
		req.Value,
		maxLen,
		req.AllowDot,
	)
	respond(w, value, err)
}

func validateOpenerCommand(w http.ResponseWriter, r *http.Request) {
	var req OpenerCommandRequest

	if err := decodeRequest(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Error: "invalid request: " + err.Error()})
		return
	}

	value, err := sanitize.SanitizeOpenerCommand(req.Value)
	respond(w, value, err)
}

