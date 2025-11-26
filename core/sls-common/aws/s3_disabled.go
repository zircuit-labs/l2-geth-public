package aws

import (
	"context"
)

type (
	S3StorerDisabled struct{}
)

func NewS3StorerDisabled() *S3StorerDisabled {
	return &S3StorerDisabled{}
}

func (s *S3StorerDisabled) Upload(ctx context.Context, key string, data []byte) error {
	return nil
}
