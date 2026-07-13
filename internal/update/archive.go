package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"path"
	"strings"
)

type binariesPayload struct {
	Client []byte
	Daemon []byte
}

func extractBinaries(archive []byte) (binariesPayload, error) {
	if len(archive) == 0 || len(archive) > maxArchiveBytes {
		return binariesPayload{}, ErrArchiveInvalid
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return binariesPayload{}, ErrArchiveInvalid
	}
	defer gzipReader.Close()

	payload, err := readTarBinaries(tar.NewReader(gzipReader))
	if err != nil {
		return binariesPayload{}, err
	}
	if err := ensureCompressedEOF(gzipReader); err != nil {
		return binariesPayload{}, err
	}
	return payload, nil
}

func readTarBinaries(reader *tar.Reader) (binariesPayload, error) {
	var payload binariesPayload
	seen := make(map[string]struct{}, 2)
	var extractedBytes int64
	entryCount := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		entryCount++
		if err != nil || entryCount > maxArchiveEntryCount || !safeArchivePath(header.Name) || unsafeArchiveType(header) {
			return binariesPayload{}, ErrArchiveInvalid
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		if header.Size < 0 || header.Size > maxBinaryBytes || extractedBytes > maxExtractedBytes-header.Size {
			return binariesPayload{}, ErrArchiveInvalid
		}
		extractedBytes += header.Size
		if header.Name != "tuibox" && header.Name != "tuiboxd" {
			if _, err := io.CopyN(io.Discard, reader, header.Size); err != nil {
				return binariesPayload{}, ErrArchiveInvalid
			}
			continue
		}
		if _, duplicate := seen[header.Name]; duplicate || header.Size <= 0 {
			return binariesPayload{}, ErrArchiveInvalid
		}
		contents, err := readExactEntry(reader, header.Size)
		if err != nil {
			return binariesPayload{}, err
		}
		seen[header.Name] = struct{}{}
		if header.Name == "tuibox" {
			payload.Client = contents
		} else {
			payload.Daemon = contents
		}
	}
	if len(payload.Client) == 0 || len(payload.Daemon) == 0 {
		return binariesPayload{}, ErrArchiveInvalid
	}
	return payload, nil
}

func safeArchivePath(name string) bool {
	if name == "" || strings.ContainsRune(name, '\x00') || path.IsAbs(name) {
		return false
	}
	cleanedInput := strings.TrimSuffix(name, "/")
	if cleanedInput == "" || path.Clean(cleanedInput) != cleanedInput {
		return false
	}
	for _, component := range strings.Split(cleanedInput, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func unsafeArchiveType(header *tar.Header) bool {
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
		return false
	default:
		return true
	}
}

func readExactEntry(reader io.Reader, size int64) ([]byte, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil || int64(len(contents)) != size {
		return nil, ErrArchiveInvalid
	}
	return contents, nil
}

func ensureCompressedEOF(reader io.Reader) error {
	var trailing [1]byte
	count, err := reader.Read(trailing[:])
	if count != 0 || err != nil && !errors.Is(err, io.EOF) {
		return ErrArchiveInvalid
	}
	return nil
}
