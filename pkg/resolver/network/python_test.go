package network

import (
	"testing"
)

func TestPythonNetworkResolver(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		statusCode   int
		expectPkg    bool
		expectedName string
		expectedVer  string
	}{
		{
			name:         "valid pypi api",
			url:          "https://pypi.org/pypi/requests/2.31.0/json",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "requests",
			expectedVer:  "2.31.0",
		},
		{
			name:         "valid wheel file",
			url:          "https://files.pythonhosted.org/packages/db/12/3456/requests-2.31.0-py3-none-any.whl",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "requests",
			expectedVer:  "2.31.0",
		},
		{
			name:         "valid source tarball",
			url:          "https://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz",
			statusCode:   200,
			expectPkg:    true,
			expectedName: "requests",
			expectedVer:  "2.31.0",
		},
		{
			name:         "failed status code",
			url:          "https://pypi.org/pypi/requests/2.31.0/json",
			statusCode:   404,
			expectPkg:    false,
		},
		{
			name:         "no status code (captured)",
			url:          "https://pypi.org/pypi/requests/2.31.0/json",
			statusCode:   0,
			expectPkg:    true,
			expectedName: "requests",
			expectedVer:  "2.31.0",
		},
		{
			name:         "invalid url matching pattern",
			url:          "https://pypi.org/something/else/2.31.0/json",
			statusCode:   200,
			expectPkg:    false,
		},
	}

	resolver := NewPythonNetworkResolver()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := NetworkConnection{
				Hostname: "pypi.org",
				IP:       "151.101.1.1",
				Exchanges: []NetworkExchange{
					{
						URL:        tc.url,
						StatusCode: tc.statusCode,
					},
				},
			}

			pkgs := resolver.Resolve(conn)
			if tc.expectPkg {
				if len(pkgs) != 1 {
					t.Fatalf("expected 1 package, got %d", len(pkgs))
				}
				pkg := pkgs[0]
				if pkg.Name != tc.expectedName {
					t.Errorf("expected name %s, got %s", tc.expectedName, pkg.Name)
				}
				if pkg.Version != tc.expectedVer {
					t.Errorf("expected version %s, got %s", tc.expectedVer, pkg.Version)
				}
			} else {
				if len(pkgs) != 0 {
					t.Fatalf("expected 0 packages, got %d", len(pkgs))
				}
			}
		})
	}
}