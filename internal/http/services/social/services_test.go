package social

import "testing"

func TestNewServices_ConstructsCoreServices(t *testing.T) {
	services := NewServices(Deps{
		Cache:        callbackCacheStub{},
		StateSigner:  callbackStateSignerStub{},
		Registry:     NewRegistry(),
		LoginCodeTTL: 30,
	})

	if services.Exchange == nil {
		t.Fatalf("expected exchange service")
	}
	if services.Result == nil {
		t.Fatalf("expected result service")
	}
	if services.Start == nil {
		t.Fatalf("expected start service")
	}
	if services.Callback == nil {
		t.Fatalf("expected callback service")
	}
	if services.Provisioning == nil {
		t.Fatalf("expected provisioning service")
	}
	if services.Token == nil {
		t.Fatalf("expected token service")
	}
}
