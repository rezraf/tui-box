package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rezraf/tui-box/internal/app"
)

const (
	defaultRepository = "rezraf/tui-box"
	defaultAPIBaseURL = "https://api.github.com"

	checksumsAssetName   = "checksums.txt"
	maxMetadataBytes     = 2 << 20
	maxChecksumsBytes    = 1 << 20
	maxArchiveBytes      = 100 << 20
	maxBinaryBytes       = 64 << 20
	maxExtractedBytes    = 160 << 20
	maxArchiveEntryCount = 1024
	maxRedirects         = 5
	defaultTimeout       = 20 * time.Second
)

var (
	ErrInvalidConfiguration = errors.New("update configuration is invalid")
	ErrUnsupportedPlatform  = errors.New("update platform is unsupported")
	ErrReleaseUnavailable   = errors.New("update release is unavailable")
	ErrReleaseInvalid       = errors.New("update release metadata is invalid")
	ErrChecksumInvalid      = errors.New("update checksums are invalid")
	ErrChecksumMismatch     = errors.New("update checksum verification failed")
	ErrArchiveInvalid       = errors.New("update archive is invalid")
	ErrResponseTooLarge     = errors.New("update response exceeds the size limit")
	ErrNetwork              = errors.New("update network request failed")
	ErrInvalidUpdate        = errors.New("update request is invalid")
	ErrInvalidInstallation  = errors.New("installed updater is invalid")
	ErrReplaceFailed        = errors.New("installed files could not be replaced")
	ErrRollbackIncomplete   = errors.New("installed files rollback was incomplete")
)

type CommandRunner func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error

type Config struct {
	CurrentVersion string
	Repository     string
	GOOS           string
	GOARCH         string
	APIBaseURL     string
	HTTPClient     *http.Client
	Timeout        time.Duration

	ExecutablePath      func() (string, error)
	RunCommand          CommandRunner
	Stdin               io.Reader
	Stdout              io.Writer
	Stderr              io.Writer
	AllowTestHTTPClient bool

	validateHelper func(string) error
}

type Updater struct {
	currentVersion string
	repository     string
	goos           string
	goarch         string
	apiBaseURL     string
	httpClient     *http.Client
	executablePath func() (string, error)
	runCommand     CommandRunner
	validateHelper func(string) error
	stdin          io.Reader
	stdout         io.Writer
	stderr         io.Writer
}

type release struct {
	TagName    string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

func New(config Config) (*Updater, error) {
	applyConfigDefaults(&config)
	if !validConfig(config) {
		return nil, ErrInvalidConfiguration
	}
	client := cloneHTTPClient(config.HTTPClient, config.Timeout)
	return &Updater{
		currentVersion: config.CurrentVersion,
		repository:     config.Repository,
		goos:           config.GOOS,
		goarch:         config.GOARCH,
		apiBaseURL:     strings.TrimSuffix(config.APIBaseURL, "/"),
		httpClient:     client,
		executablePath: config.ExecutablePath,
		runCommand:     config.RunCommand,
		validateHelper: config.validateHelper,
		stdin:          config.Stdin,
		stdout:         config.Stdout,
		stderr:         config.Stderr,
	}, nil
}

func applyConfigDefaults(config *Config) {
	if config.Repository == "" {
		config.Repository = defaultRepository
	}
	if config.GOOS == "" {
		config.GOOS = runtime.GOOS
	}
	if config.GOARCH == "" {
		config.GOARCH = runtime.GOARCH
	}
	if config.APIBaseURL == "" {
		config.APIBaseURL = defaultAPIBaseURL
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultTimeout
	}
	if config.ExecutablePath == nil {
		config.ExecutablePath = defaultExecutablePath
	}
	if config.RunCommand == nil {
		config.RunCommand = defaultCommandRunner
	}
	if config.validateHelper == nil {
		config.validateHelper = validatePrivilegeHelper
	}
}

func validConfig(config Config) bool {
	if !validRepository(config.Repository) || !supportedPlatform(config.GOOS, config.GOARCH) {
		return false
	}
	if _, ok := parseStableVersion(config.CurrentVersion); !ok {
		return false
	}
	parsed, err := url.Parse(config.APIBaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return config.Timeout > 0 && config.Timeout <= time.Minute
}

func validRepository(repository string) bool {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 100 {
			return false
		}
		for _, character := range part {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
				continue
			}
			return false
		}
	}
	return true
}

func supportedPlatform(goos, goarch string) bool {
	return (goos == "linux" || goos == "darwin") && (goarch == "amd64" || goarch == "arm64")
}

func cloneHTTPClient(source *http.Client, timeout time.Duration) *http.Client {
	client := &http.Client{}
	if source != nil {
		*client = *source
	}
	client.Timeout = timeout
	client.CheckRedirect = secureRedirect
	return client
}

func secureRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return ErrNetwork
	}
	if request.URL.Scheme != "https" {
		return ErrNetwork
	}
	request.Header.Del("Authorization")
	request.Header.Del("Cookie")
	return nil
}

func (updater *Updater) Check(ctx context.Context) (app.UpdateInfo, error) {
	releases, err := updater.fetchReleases(ctx)
	if err != nil {
		return app.UpdateInfo{}, err
	}
	latest, found := latestStableRelease(releases)
	if !found {
		return app.UpdateInfo{}, ErrReleaseUnavailable
	}
	comparison, ok := compareStableVersions(updater.currentVersion, latest.TagName)
	if !ok {
		return app.UpdateInfo{}, ErrReleaseInvalid
	}
	return app.UpdateInfo{
		CurrentVersion: updater.currentVersion,
		LatestVersion:  canonicalVersion(latest.TagName),
		Available:      comparison < 0,
	}, nil
}

func (updater *Updater) fetchReleases(ctx context.Context) ([]release, error) {
	endpoint := updater.apiBaseURL + "/repos/" + updater.repository + "/releases?per_page=100"
	body, err := updater.getBounded(ctx, endpoint, maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	var releases []release
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&releases); err != nil || len(releases) > 100 {
		return nil, ErrReleaseInvalid
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, ErrReleaseInvalid
	}
	return releases, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrReleaseInvalid
	}
	return nil
}

func latestStableRelease(releases []release) (release, bool) {
	var selected release
	found := false
	for _, candidate := range releases {
		if candidate.Draft || candidate.Prerelease {
			continue
		}
		if _, ok := parseStableVersion(candidate.TagName); !ok {
			continue
		}
		if !found {
			selected, found = candidate, true
			continue
		}
		if comparison, _ := compareStableVersions(candidate.TagName, selected.TagName); comparison > 0 {
			selected = candidate
		}
	}
	return selected, found
}

func findStableRelease(releases []release, version string) (release, bool) {
	canonical := canonicalVersion(version)
	for _, candidate := range releases {
		if candidate.Draft || candidate.Prerelease {
			continue
		}
		if canonicalVersion(candidate.TagName) == canonical {
			if _, ok := parseStableVersion(candidate.TagName); ok {
				return candidate, true
			}
		}
	}
	return release{}, false
}

type stableVersion [3]uint64

func parseStableVersion(value string) (stableVersion, bool) {
	value = strings.TrimPrefix(value, "v")
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return stableVersion{}, false
	}
	var version stableVersion
	for index, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return stableVersion{}, false
		}
		parsed, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return stableVersion{}, false
		}
		version[index] = parsed
	}
	return version, true
}

func compareStableVersions(left, right string) (int, bool) {
	leftVersion, leftOK := parseStableVersion(left)
	rightVersion, rightOK := parseStableVersion(right)
	if !leftOK || !rightOK {
		return 0, false
	}
	for index := range leftVersion {
		if leftVersion[index] < rightVersion[index] {
			return -1, true
		}
		if leftVersion[index] > rightVersion[index] {
			return 1, true
		}
	}
	return 0, true
}

func canonicalVersion(value string) string {
	version, ok := parseStableVersion(value)
	if !ok {
		return ""
	}
	return fmt.Sprintf("v%d.%d.%d", version[0], version[1], version[2])
}

func selectAssets(release release, goos, goarch string) (releaseAsset, releaseAsset, error) {
	if !supportedPlatform(goos, goarch) {
		return releaseAsset{}, releaseAsset{}, ErrUnsupportedPlatform
	}
	archiveName := archiveAssetName(goos, goarch)
	archive, archiveCount := exactAsset(release.Assets, archiveName)
	checksums, checksumCount := exactAsset(release.Assets, checksumsAssetName)
	if archiveCount != 1 || checksumCount != 1 || !validAsset(archive) || !validAsset(checksums) {
		return releaseAsset{}, releaseAsset{}, ErrReleaseInvalid
	}
	return archive, checksums, nil
}

func archiveAssetName(goos, goarch string) string {
	return "tuibox_" + goos + "_" + goarch + ".tar.gz"
}

func exactAsset(assets []releaseAsset, name string) (releaseAsset, int) {
	var selected releaseAsset
	count := 0
	for _, asset := range assets {
		if asset.Name == name {
			selected = asset
			count++
		}
	}
	return selected, count
}

func validAsset(asset releaseAsset) bool {
	parsed, err := url.Parse(asset.URL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func parseChecksum(document []byte, archiveName string) (string, error) {
	if len(document) == 0 || len(document) > maxChecksumsBytes {
		return "", ErrChecksumInvalid
	}
	var digest string
	for _, line := range strings.Split(string(document), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return "", ErrChecksumInvalid
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size {
			return "", ErrChecksumInvalid
		}
		if fields[1] == archiveName {
			if digest != "" {
				return "", ErrChecksumInvalid
			}
			digest = strings.ToLower(fields[0])
		}
	}
	if digest == "" {
		return "", ErrChecksumInvalid
	}
	return digest, nil
}

func (updater *Updater) downloadRelease(ctx context.Context, selected release) ([]byte, error) {
	archive, checksums, err := selectAssets(selected, updater.goos, updater.goarch)
	if err != nil {
		return nil, err
	}
	checksumDocument, err := updater.getBounded(ctx, checksums.URL, maxChecksumsBytes)
	if err != nil {
		return nil, err
	}
	digest, err := parseChecksum(checksumDocument, archive.Name)
	if err != nil {
		return nil, err
	}
	return updater.downloadVerifiedArchive(ctx, archive.URL, digest)
}

func (updater *Updater) downloadVerifiedArchive(ctx context.Context, assetURL, expectedDigest string) ([]byte, error) {
	decoded, err := hex.DecodeString(expectedDigest)
	if err != nil || len(decoded) != sha256.Size {
		return nil, ErrChecksumInvalid
	}
	archive, err := updater.getBounded(ctx, assetURL, maxArchiveBytes)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(archive)
	if !bytes.Equal(actual[:], decoded) {
		return nil, ErrChecksumMismatch
	}
	return archive, nil
}

func (updater *Updater) getBounded(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrNetwork
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, ErrNetwork
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "TuiBox-Updater")
	response, err := updater.httpClient.Do(request)
	if err != nil {
		return nil, contextOrNetworkError(ctx)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, ErrNetwork
	}
	if response.ContentLength > limit {
		return nil, ErrResponseTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, contextOrNetworkError(ctx)
	}
	if int64(len(body)) > limit {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

func contextOrNetworkError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrNetwork
}
