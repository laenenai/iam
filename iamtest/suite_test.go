package iamtest_test

import (
	"context"
	"testing"

	"github.com/laenenai/iam"
	"github.com/laenenai/iam/iamtest"
)

func TestMemorySuite(t *testing.T) {
	iamtest.RunSuite(t, func(t *testing.T) *iam.IAM {
		v, err := iam.NewMemory(context.Background(), iam.Config{})
		if err != nil {
			t.Fatal(err)
		}
		return v
	})
}
