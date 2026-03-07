package social

import (
	"context"
	"testing"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/social"
)

type resultCacheStub struct {
	data       map[string][]byte
	deleteHits int
}

func (c *resultCacheStub) Get(key string) ([]byte, bool) {
	v, ok := c.data[key]
	return v, ok
}

func (c *resultCacheStub) Delete(key string) error {
	c.deleteHits++
	delete(c.data, key)
	return nil
}

func TestResultService_ValidatesCode(t *testing.T) {
	service := NewResultService(ResultDeps{
		Cache: &resultCacheStub{data: map[string][]byte{}},
	})

	_, err := service.GetResult(context.Background(), dto.ResultRequest{})
	if err != ErrResultCodeMissing {
		t.Fatalf("expected ErrResultCodeMissing, got %v", err)
	}

	_, err = service.GetResult(context.Background(), dto.ResultRequest{Code: "missing"})
	if err != ErrResultCodeNotFound {
		t.Fatalf("expected ErrResultCodeNotFound, got %v", err)
	}
}

func TestResultService_ConsumesCodeWhenPeekDisabled(t *testing.T) {
	cache := &resultCacheStub{
		data: map[string][]byte{
			"social:code:code-a": []byte(`{"ok":true}`),
		},
	}
	service := NewResultService(ResultDeps{
		Cache: cache,
	})

	result, err := service.GetResult(context.Background(), dto.ResultRequest{
		Code: "code-a",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil || result.Code != "code-a" || result.Peek {
		t.Fatalf("unexpected result payload: %#v", result)
	}
	if cache.deleteHits != 1 {
		t.Fatalf("expected one delete call, got %d", cache.deleteHits)
	}
}

func TestResultService_PeekOnlyWhenDebugEnabled(t *testing.T) {
	cache := &resultCacheStub{
		data: map[string][]byte{
			"social:code:code-a": []byte(`{"ok":true}`),
		},
	}
	service := NewResultService(ResultDeps{
		Cache:     cache,
		DebugPeek: true,
	})

	result, err := service.GetResult(context.Background(), dto.ResultRequest{
		Code: "code-a",
		Peek: true,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil || !result.Peek {
		t.Fatalf("expected peek=true, got %#v", result)
	}
	if cache.deleteHits != 0 {
		t.Fatalf("expected no delete call in peek mode, got %d", cache.deleteHits)
	}
}
