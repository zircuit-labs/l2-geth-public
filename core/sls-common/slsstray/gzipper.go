package slsstray

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type GZipper struct{}

func NewGZipper() *GZipper {
	return &GZipper{}
}

// StoreGzipJson stores gzip compressed go struct at storage path: basePath/<timestamp-unix>/<filename>.json.gz
func (g *GZipper) StoreGzipJson(data any, basePath string, filename LocalStorageFileName, timestamp time.Time) (string, error) {

	timestampStr := fmt.Sprintf("%d", timestamp.Unix())
	dirPath := filepath.Join(basePath, timestampStr)

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return "", err
	}

	// Marshal struct to JSON
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	filePath, err := g.incrementFilename(filepath.Join(dirPath, fmt.Sprintf("%s.json.gz", filename)))
	if err != nil {
		return filePath, err
	}

	// Create file
	file, err := os.Create(filePath)
	if err != nil {
		return filePath, err
	}
	defer file.Close()

	// Gzip writer
	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	// Write JSON to file
	if _, err = gzipWriter.Write(jsonBytes); err != nil {
		return filePath, err
	}

	return filePath, nil
}

// incrementFilename ensures a unique filename by appending (1), (2), etc.
// It handles multi-part extensions like .json.gz
func (g *GZipper) incrementFilename(filename string) (string, error) {
	// Define special multi-part extensions
	multiExts := []string{".json.gz"}

	ext := filepath.Ext(filename) // fallback single extension
	base := strings.TrimSuffix(filename, ext)

	// Check if filename ends with any known multi-part extension
	for _, mext := range multiExts {
		if strings.HasSuffix(filename, mext) {
			ext = mext
			base = strings.TrimSuffix(filename, mext)
			break
		}
	}

	newName := filename
	counter := 1

	for {
		_, err := os.Stat(newName)
		if os.IsNotExist(err) {
			return newName, nil // safe
		}
		if err != nil {
			return "", err // unexpected error
		}

		// File exists → increment
		newName = fmt.Sprintf("%s(%d)%s", base, counter, ext)
		counter++
	}
}

// openGzipJson opens and returns data from a gzipped file
func (g *GZipper) OpenGzipJson(filePath string) ([]byte, error) {
	// Open the gzip file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a gzip reader
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	// Read all decompressed data
	return io.ReadAll(gzipReader)
}
