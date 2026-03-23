package attestation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func ParseWitnessFile(path string, typeFilter []string) ([]TypedAttestation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read witness file: %w", err)
	}

	return ParseWitnessData(data, typeFilter)
}

func ParseWitnessData(data []byte, typeFilter []string) ([]TypedAttestation, error) {
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation JSON: %w", err)
	}

	// Some witness outputs are direct in-toto statements (not DSSE envelopes).
	if _, hasPredicate := topLevel["predicate"]; hasPredicate {
		var statement InTotoStatement
		if err := json.Unmarshal(data, &statement); err != nil {
			return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
		}
		return extractAttestations(statement.Predicate, typeFilter)
	}

	var rawEnvelope struct {
		PayloadType string          `json:"payloadType"`
		Payload     json.RawMessage `json:"payload"`
		Signatures  []Signature     `json:"signatures"`
	}
	if err := json.Unmarshal(data, &rawEnvelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DSSE envelope: %w", err)
	}

	if len(rawEnvelope.Payload) == 0 {
		return nil, fmt.Errorf("missing payload in attestation JSON (expected direct in-toto statement or DSSE envelope)")
	}

	payload, err := decodeEnvelopePayload(rawEnvelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
	}

	var statement InTotoStatement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}

	return extractAttestations(statement.Predicate, typeFilter)
}

func decodeEnvelopePayload(rawPayload json.RawMessage) ([]byte, error) {
	var payloadStr string
	if err := json.Unmarshal(rawPayload, &payloadStr); err == nil {
		decoded, decodeErr := decodeBase64Any(payloadStr)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return decoded, nil
	}

	// If payload is already embedded JSON, use it as-is.
	if len(rawPayload) > 0 && (rawPayload[0] == '{' || rawPayload[0] == '[') {
		return rawPayload, nil
	}

	return nil, fmt.Errorf("unsupported payload format")
}

func decodeBase64Any(s string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding failed: %w", err)
	}
	return decoded, nil
}

func extractAttestations(predicate map[string]interface{}, typeFilter []string) ([]TypedAttestation, error) {
	var result []TypedAttestation

	filterSet := make(map[string]struct{})
	if len(typeFilter) > 0 {
		for _, t := range typeFilter {
			normalized := normalizeAttestationType(t)
			if normalized == "" {
				continue
			}
			filterSet[normalized] = struct{}{}
		}
	}

	attestationsRaw, ok := predicate["attestations"]
	if !ok {
		return result, nil
	}

	attestations, ok := attestationsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("attestations is not an array")
	}

	for _, att := range attestations {
		attMap, ok := att.(map[string]interface{})
		if !ok {
			continue
		}

		typed := TypedAttestation{
			Data: make(map[string]interface{}),
		}

		if typeVal, ok := attMap["type"].(string); ok {
			typed.Type = canonicalAttestationType(typeVal)
		}

		if len(filterSet) > 0 {
			if _, ok := filterSet[typed.Type]; !ok {
				continue
			}
		}

		if attData, ok := attMap["attestation"].(map[string]interface{}); ok {
			typed.Data = attData
		}

		result = append(result, typed)
	}

	return result, nil
}

func normalizeAttestationType(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func canonicalAttestationType(rawType string) string {
	t := normalizeAttestationType(rawType)
	if t == "" {
		return ""
	}

	// Handles both shorthand types and URI-style types.
	parts := strings.Split(t, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		segment := strings.TrimSpace(parts[i])
		if segment == "" || strings.HasPrefix(segment, "v") {
			continue
		}
		t = segment
		break
	}

	if t == "commandrun" {
		return "command-run"
	}

	return t
}

// ExtractorChain to delegate extraction to type-specific extractors
func ExtractFilesFromAttestations(attestations []TypedAttestation, types []string) []FileInfo {
	chain := NewExtractorChain()
	return chain.ExtractAll(attestations, types)
}
