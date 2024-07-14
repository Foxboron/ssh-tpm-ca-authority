package main

import (
	"context"
	"testing"
)

func TestMain(t *testing.T) {
	ctx := context.Background()
	go run(ctx)
	defer ctx.Done()
}
