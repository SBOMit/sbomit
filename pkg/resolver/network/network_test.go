package network

import (
	"sort"
	"testing"
)

// conn builds a connection carrying one successful exchange per URL, with a
// body hash — witness records one for every intercepted response.
func conn(hostname string, urls ...string) NetworkConnection {
	c := NetworkConnection{Hostname: hostname, Protocol: "https"}
	for _, u := range urls {
		c.Exchanges = append(c.Exchanges, NetworkExchange{
			URL:        u,
			Method:     "GET",
			StatusCode: 200,
			BodyHash:   "body-digest",
		})
	}
	return c
}

func resolved(t *testing.T, c NetworkConnection) []string {
	t.Helper()
	out := []string{}
	for _, d := range NewChain().ResolveAll([]NetworkConnection{c}) {
		out = append(out, d.Package.PURL)
	}
	sort.Strings(out)
	return out
}

func TestChainResolvesNpmTarballs(t *testing.T) {
	got := resolved(t, conn("registry.npmjs.org",
		"https://registry.npmjs.org:443/@actions/http-client/-/http-client-2.2.3.tgz",
		"https://registry.npmjs.org:443/semver/-/semver-7.8.5.tgz",
	))

	want := []string{"pkg:npm/@actions/http-client@2.2.3", "pkg:npm/semver@7.8.5"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

// Yarn fetches from its own registry host, and percent-encodes the scope
// separator in metadata requests.
func TestChainResolvesYarnRegistry(t *testing.T) {
	got := resolved(t, conn("registry.yarnpkg.com",
		"https://registry.yarnpkg.com:443/@actions/cache/-/cache-6.2.0.tgz",
	))

	if len(got) != 1 || got[0] != "pkg:npm/@actions/cache@6.2.0" {
		t.Fatalf("expected pkg:npm/@actions/cache@6.2.0, got %v", got)
	}
}

// crates.io serves the artifact from a /download endpoint with no filename, so
// the name and version come from the path segments.
func TestChainResolvesCratesIoDownloadEndpoint(t *testing.T) {
	got := resolved(t, conn("static.crates.io",
		"https://static.crates.io:443/crates/anstream/0.6.17/download",
	))

	if len(got) != 1 || got[0] != "pkg:cargo/anstream@0.6.17" {
		t.Fatalf("expected pkg:cargo/anstream@0.6.17, got %v", got)
	}
}

func TestChainResolvesGoProxy(t *testing.T) {
	got := resolved(t, conn("proxy.golang.org",
		"https://proxy.golang.org:443/github.com/lib/pq/@v/v1.11.1.zip",
	))

	if len(got) != 1 || got[0] != "pkg:golang/github.com/lib/pq@v1.11.1" {
		t.Fatalf("expected pkg:golang/github.com/lib/pq@v1.11.1, got %v", got)
	}
}

func TestChainResolvesPyPI(t *testing.T) {
	got := resolved(t, conn("files.pythonhosted.org",
		"https://files.pythonhosted.org:443/packages/5f/80/91f/hatchling-1.32.4-py3-none-any.whl",
	))

	if len(got) != 1 || got[0] != "pkg:pypi/hatchling@1.32.4" {
		t.Fatalf("expected pkg:pypi/hatchling@1.32.4, got %v", got)
	}
}

func TestChainResolvesMavenCentral(t *testing.T) {
	got := resolved(t, conn("repo.maven.apache.org",
		"https://repo.maven.apache.org:443/maven2/org/eclipse/tycho/tycho-core/5.0.3/tycho-core-5.0.3.jar",
	))

	if len(got) != 1 || got[0] != "pkg:maven/org.eclipse.tycho/tycho-core@5.0.3" {
		t.Fatalf("expected pkg:maven/org.eclipse.tycho/tycho-core@5.0.3, got %v", got)
	}
}

// jitpack and most mirrors serve Maven paths at the host root, with no
// /maven2/ prefix — the URL counterpart of a local repository at a custom root.
func TestChainResolvesMavenLayoutWithoutPrefix(t *testing.T) {
	got := resolved(t, conn("jitpack.io",
		"https://jitpack.io:443/com/github/iBotPeaches/smali/smali-baksmali/b6365a84f4/smali-baksmali-b6365a84f4.jar",
	))

	want := "pkg:maven/com.github.iBotPeaches.smali/smali-baksmali@b6365a84f4"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected %s, got %v", want, got)
	}
}

func TestChainResolvesCondaChannel(t *testing.T) {
	got := resolved(t, conn("conda.anaconda.org",
		"https://conda.anaconda.org:443/conda-forge/noarch/affine-3.0.1-pyhecae5ae_0.conda",
	))

	want := "pkg:conda/affine@3.0.1?build=pyhecae5ae_0"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected %s, got %v", want, got)
	}
}

// Index and repodata requests name no package version.
func TestChainIgnoresRegistryMetadata(t *testing.T) {
	for host, url := range map[string]string{
		"conda.anaconda.org": "https://conda.anaconda.org:443/conda-forge/linux-64/repodata_shards.msgpack.zst",
		"index.crates.io":    "https://index.crates.io:443/an/yh/anyhow",
		"registry.npmjs.org": "https://registry.npmjs.org:443/pnpm",
	} {
		if got := resolved(t, conn(host, url)); len(got) != 0 {
			t.Errorf("%s: expected no packages from metadata, got %v", host, got)
		}
	}
}

// A failed download is not evidence that a package was used.
func TestChainIgnoresFailedResponses(t *testing.T) {
	c := NetworkConnection{Hostname: "registry.npmjs.org"}
	c.Exchanges = append(c.Exchanges, NetworkExchange{
		URL:        "https://registry.npmjs.org:443/semver/-/semver-7.8.5.tgz",
		StatusCode: 404,
	})

	if got := resolved(t, c); len(got) != 0 {
		t.Fatalf("expected no packages from a 404, got %v", got)
	}
}

// The response body hash is the digest of the artifact the registry served —
// for a package whose artifact is not left on disk it is the only one available.
func TestChainCarriesTheArtifactDigest(t *testing.T) {
	packages := NewChain().ResolveAll([]NetworkConnection{
		conn("registry.npmjs.org", "https://registry.npmjs.org:443/semver/-/semver-7.8.5.tgz"),
	})

	if len(packages) != 1 {
		t.Fatalf("expected one package, got %d", len(packages))
	}
	if !packages[0].Artifact {
		t.Fatal("a .tgz is the package artifact")
	}
	if got := packages[0].Digests; len(got) != 1 || got[0].Value != "body-digest" {
		t.Fatalf("expected the response body digest, got %v", got)
	}
}

// Metadata requests are reported but not marked as the artifact.
func TestChainMarksMetadataRequestsAsNotTheArtifact(t *testing.T) {
	for _, tc := range []struct {
		host, url string
		artifact  bool
	}{
		{"files.pythonhosted.org", "https://files.pythonhosted.org/packages/a/b/attrs-26.1.0-py3-none-any.whl.metadata", false},
		{"files.pythonhosted.org", "https://files.pythonhosted.org/packages/a/b/attrs-26.1.0-py3-none-any.whl", true},
		{"files.pythonhosted.org", "https://files.pythonhosted.org/packages/a/b/attrs-26.1.0.tar.gz", true},
		{"pypi.org", "https://pypi.org/pypi/attrs/26.1.0/json", false},
		{"proxy.golang.org", "https://proxy.golang.org/github.com/lib/pq/@v/v1.11.1.info", false},
		{"proxy.golang.org", "https://proxy.golang.org/github.com/lib/pq/@v/v1.11.1.mod", false},
		{"proxy.golang.org", "https://proxy.golang.org/github.com/lib/pq/@v/v1.11.1.zip", true},
		{"registry.npmjs.org", "https://registry.npmjs.org/semver/7.8.5", false},
		{"repo.maven.apache.org", "https://repo.maven.apache.org/maven2/org/apache/maven/maven-parent/47/maven-parent-47.pom", false},
	} {
		got := NewChain().ResolveAll([]NetworkConnection{conn(tc.host, tc.url)})
		if len(got) != 1 {
			t.Errorf("%s: expected one download, got %d", tc.url, len(got))
			continue
		}
		if got[0].Artifact != tc.artifact {
			t.Errorf("%s: artifact = %v, want %v", tc.url, got[0].Artifact, tc.artifact)
		}
	}
}

// Every request for a package is kept, not just the first (the pom).
func TestChainKeepsEveryRequestForAPackage(t *testing.T) {
	downloads := NewChain().ResolveAll([]NetworkConnection{
		conn("repo.maven.apache.org",
			"https://repo.maven.apache.org:443/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom",
			"https://repo.maven.apache.org:443/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"),
	})

	if len(downloads) != 2 {
		t.Fatalf("expected the pom and the jar, got %d", len(downloads))
	}
	var jar bool
	for _, d := range downloads {
		jar = jar || (d.Artifact && len(d.Digests) == 1)
	}
	if !jar {
		t.Fatalf("expected the jar with its digest, got %+v", downloads)
	}
}

// The client is named from its User-Agent, which is what lets a consumer tell
// a download npm made from one pnpm made, in the same ecosystem.
func TestChainNamesTheClientThatMadeTheRequest(t *testing.T) {
	for _, tc := range []struct{ host, ua, want string }{
		{"registry.npmjs.org", "pnpm/10.34.6 npm/? node/v24.21.0 linux x64", "pnpm"},
		{"registry.npmjs.org", "npm/10.9.0 node/v22.11.0 linux x64 workspaces/false", "npm"},
		// Yarn berry sends its HTTP library's name; its default host names it.
		{"registry.yarnpkg.com", "got (https://github.com/sindresorhus/got)", "yarn"},
		{"files.pythonhosted.org", "pip/24.0 {...}", "pip"},
		{"proxy.golang.org", "Go-http-client/1.1", "go"},
		{"repo.maven.apache.org", "Gradle/9.7.1 (Linux;6.8;amd64)", "gradle"},
		{"example.org", "curl/8.0", ""},
	} {
		if got := clientPkgMgr(tc.ua, tc.host); got != tc.want {
			t.Errorf("%q on %s: got %q, want %q", tc.ua, tc.host, got, tc.want)
		}
	}
}

// An empty body hashes to the empty-content digest, which identifies nothing.
func TestChainDropsTheEmptyContentDigest(t *testing.T) {
	c := conn("static.crates.io", "https://static.crates.io/crates/anstream/0.6.17/download")
	c.Exchanges[0].BodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	got := NewChain().ResolveAll([]NetworkConnection{c})
	if len(got) != 1 || len(got[0].Digests) != 0 {
		t.Fatalf("expected the download kept without a digest, got %+v", got)
	}
}

// Hosts no resolver claims are ignored rather than guessed at.
func TestChainIgnoresUnknownHosts(t *testing.T) {
	if got := resolved(t, conn("example.com", "https://example.com/foo-1.0.tgz")); len(got) != 0 {
		t.Fatalf("expected no packages from an unknown host, got %v", got)
	}
}

// A repository root mid-path (dl.google.com/dl/android/maven2/).
func TestChainFindsTheRepositoryRootMidPath(t *testing.T) {
	got := resolved(t, conn("dl.google.com",
		"https://dl.google.com:443/dl/android/maven2/com/android/tools/r8/9.1.31/r8-9.1.31.pom",
	))

	want := "pkg:maven/com.android.tools/r8@9.1.31"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected %s, got %v", want, got)
	}
}
