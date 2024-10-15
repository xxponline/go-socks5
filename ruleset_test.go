package socks5

import (
	"testing"

	"golang.org/x/net/context"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if _, ok := r.Allow(ctx, &EnhancedRequest{S5Request: S5Request{Command: ConnectCommand}}); !ok {
		t.Fatalf("expect connect")
	}

	if _, ok := r.Allow(ctx, &EnhancedRequest{S5Request: S5Request{Command: BindCommand}}); ok {
		t.Fatalf("do not expect bind")
	}

	if _, ok := r.Allow(ctx, &EnhancedRequest{S5Request: S5Request{Command: AssociateCommand}}); ok {
		t.Fatalf("do not expect associate")
	}
}
