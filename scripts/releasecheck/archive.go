package releasecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"
)

func CreateSourceArchive(snapshot Snapshot) ([]byte, error) {
	var output bytes.Buffer
	compressor, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	archive := tar.NewWriter(compressor)
	if err := writeArchiveFiles(archive, snapshot); err != nil {
		_ = archive.Close()
		_ = compressor.Close()
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	if err := compressor.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeArchiveFiles(archive *tar.Writer, snapshot Snapshot) error {
	for _, name := range sortedSnapshotPaths(snapshot) {
		file := snapshot[name]
		header, err := archiveHeader(name, file)
		if err != nil {
			return err
		}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := archive.Write(file.Data); err != nil {
				return err
			}
		}
	}
	return nil
}

func archiveHeader(name string, file File) (*tar.Header, error) {
	if !validRepositoryPath(name) || file.Path != name {
		return nil, fmt.Errorf("invalid archive path %q", name)
	}
	header := &tar.Header{
		Name:    name,
		Mode:    int64(file.Mode.Perm()),
		ModTime: time.Unix(0, 0).UTC(),
	}
	switch {
	case file.Mode.IsRegular():
		header.Typeflag = tar.TypeReg
		header.Size = int64(len(file.Data))
	case file.Mode&fs.ModeSymlink != 0:
		header.Typeflag = tar.TypeSymlink
		header.Linkname = string(file.Data)
	default:
		return nil, fmt.Errorf("unsupported archive file type for %s", name)
	}
	return header, nil
}

func ReadSourceArchive(contents []byte) (Snapshot, error) {
	if len(contents) > maxSourceArchiveSize {
		return nil, errors.New("source archive exceeds size limit")
	}
	compressed := bytes.NewReader(contents)
	decompressor, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, err
	}
	decompressor.Multistream(false)
	snapshot, err := readTarFiles(tar.NewReader(decompressor))
	closeErr := decompressor.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if compressed.Len() != 0 {
		return nil, errors.New("source archive has trailing compressed data")
	}
	return snapshot, nil
}

func readTarFiles(archive *tar.Reader) (Snapshot, error) {
	snapshot := make(Snapshot)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return snapshot, nil
		}
		if err != nil {
			return nil, err
		}
		file, err := readArchiveFile(archive, header)
		if err != nil {
			return nil, err
		}
		if _, exists := snapshot[file.Path]; exists {
			return nil, fmt.Errorf("duplicate archive path %q", file.Path)
		}
		snapshot[file.Path] = file
	}
}

func readArchiveFile(archive *tar.Reader, header *tar.Header) (File, error) {
	if !validRepositoryPath(header.Name) {
		return File{}, fmt.Errorf("invalid archive path %q", header.Name)
	}
	mode := fs.FileMode(header.Mode & 0o777)
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		if header.Size < 0 || header.Size > maxSourceFileSize {
			return File{}, fmt.Errorf("archive file %s exceeds size limit", header.Name)
		}
		contents, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil {
			return File{}, err
		}
		if int64(len(contents)) != header.Size {
			return File{}, fmt.Errorf("archive file %s has invalid size", header.Name)
		}
		return File{Path: header.Name, Mode: mode, Data: contents}, nil
	case tar.TypeSymlink:
		return File{Path: header.Name, Mode: mode | fs.ModeSymlink, Data: []byte(header.Linkname)}, nil
	default:
		return File{}, fmt.Errorf("unsupported archive entry type for %s", header.Name)
	}
}

func EqualSnapshots(want, got Snapshot) error {
	if len(want) != len(got) {
		return fmt.Errorf("file count = %d, want %d", len(got), len(want))
	}
	for name, wantFile := range want {
		gotFile, ok := got[name]
		if !ok {
			return fmt.Errorf("archive is missing %s", name)
		}
		if wantFile.Mode.Type() != gotFile.Mode.Type() || wantFile.Mode.Perm() != gotFile.Mode.Perm() {
			return fmt.Errorf("mode for %s = %v, want %v", name, gotFile.Mode, wantFile.Mode)
		}
		if !bytes.Equal(wantFile.Data, gotFile.Data) {
			return fmt.Errorf("contents differ for %s", name)
		}
	}
	return nil
}
