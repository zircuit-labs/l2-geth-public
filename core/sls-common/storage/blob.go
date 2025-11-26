package storage

import "context"

//go:generate go tool mockgen -source blob.go -destination mock_blocb.go -package storage

type S3Storer interface {
	Upload(ctx context.Context, key string, data []byte) error
}
