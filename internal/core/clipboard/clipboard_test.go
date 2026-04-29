package clipboard

import (
	"testing"
	"time"
)

func TestPolicyDefaults(t *testing.T) {
	p := Policy{
		ClearAfter:     45 * time.Second,
		CloseAfterCopy: true,
	}
	if p.ClearAfter != 45*time.Second {
		t.Errorf("expected ClearAfter 45s, got %v", p.ClearAfter)
	}
	if !p.CloseAfterCopy {
		t.Error("expected CloseAfterCopy true")
	}
}

func TestPolicyZeroValue(t *testing.T) {
	var p Policy
	if p.ClearAfter != 0 {
		t.Errorf("expected zero ClearAfter, got %v", p.ClearAfter)
	}
	if p.CloseAfterCopy {
		t.Error("expected zero CloseAfterCopy false")
	}
}

func TestPolicyCustom(t *testing.T) {
	p := Policy{
		ClearAfter:     30 * time.Second,
		CloseAfterCopy: false,
	}
	if p.ClearAfter != 30*time.Second {
		t.Errorf("expected ClearAfter 30s, got %v", p.ClearAfter)
	}
	if p.CloseAfterCopy {
		t.Error("expected CloseAfterCopy false")
	}
}
