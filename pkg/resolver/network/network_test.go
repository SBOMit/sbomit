package network

import (
	"testing"
)

func TestExtractConnections(t *testing.T) {
	data := map[string]interface{}{
		"network_trace": map[string]interface{}{
			"connections": []interface{}{
				map[string]interface{}{
					"protocol": "tcp",
					"destination": map[string]interface{}{
						"hostname": "proxy.golang.org",
						"ip":       "142.250.190.49",
					},
					"http_exchanges": []interface{}{
						map[string]interface{}{
							"request": map[string]interface{}{
								"url":    "https://proxy.golang.org/github.com/google/uuid/@v/v1.3.0.zip",
								"method": "GET",
								"headers": map[string]interface{}{
									"Referer": []interface{}{"https://example.com"},
								},
							},
							"response": map[string]interface{}{
								"status_code": float64(200),
								"body": map[string]interface{}{
									"hash": "abcdef123456",
								},
							},
						},
					},
				},
				map[string]interface{}{
					"protocol": "tcp",
					// missing destination, should be skipped
				},
			},
		},
	}

	conns := extractFromData(data)

	if len(conns) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(conns))
	}

	conn := conns[0]
	if conn.Hostname != "proxy.golang.org" {
		t.Errorf("Expected hostname 'proxy.golang.org', got '%s'", conn.Hostname)
	}
	if conn.IP != "142.250.190.49" {
		t.Errorf("Expected IP '142.250.190.49', got '%s'", conn.IP)
	}
	if conn.Protocol != "tcp" {
		t.Errorf("Expected protocol 'tcp', got '%s'", conn.Protocol)
	}
	if len(conn.Exchanges) != 1 {
		t.Fatalf("Expected 1 exchange, got %d", len(conn.Exchanges))
	}

	ex := conn.Exchanges[0]
	if ex.URL != "https://proxy.golang.org/github.com/google/uuid/@v/v1.3.0.zip" {
		t.Errorf("Expected URL, got '%s'", ex.URL)
	}
	if ex.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", ex.StatusCode)
	}
	if ex.BodyHash != "abcdef123456" {
		t.Errorf("Expected body hash, got '%s'", ex.BodyHash)
	}
	if ex.Referer != "https://example.com" {
		t.Errorf("Expected referer, got '%s'", ex.Referer)
	}
}

func TestIsSuccessful(t *testing.T) {
	if !isSuccessful(0) {
		t.Errorf("Expected 0 to be successful")
	}
	if !isSuccessful(200) {
		t.Errorf("Expected 200 to be successful")
	}
	if !isSuccessful(299) {
		t.Errorf("Expected 299 to be successful")
	}
	if isSuccessful(404) {
		t.Errorf("Expected 404 to not be successful")
	}
	if isSuccessful(500) {
		t.Errorf("Expected 500 to not be successful")
	}
}
