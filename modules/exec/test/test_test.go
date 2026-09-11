package test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/friz-zy/statekit/internal/facts"
	"github.com/friz-zy/statekit/internal/runtime"
)

func sleepRT() *runtime.Runtime {
	return &runtime.Runtime{
		Facts: facts.ForTesting(facts.Overrides{}),
		FS:    runtime.NewMemoryFS(),
	}
}

func TestRegisterInstallsSleep(t *testing.T) {
	reg := runtime.NewExecRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	want := []string{"test.echo", "test.ping", "test.sleep"}
	if got := reg.Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	fn, ok := reg.Get("test.sleep")
	if !ok {
		t.Fatal("test.sleep missing after Register")
	}
	if _, isSleep := fn.(sleepFunc); !isSleep {
		t.Fatalf("test.sleep registered by wrong type %T", fn)
	}
}

func TestSleepZeroLengthReturnsTrue(t *testing.T) {
	value, err := (sleepFunc{}).Execute(context.Background(), sleepRT(), &sleepArgs{Length: 0})
	if err != nil {
		t.Fatalf("length 0: %v", err)
	}
	if value != true {
		t.Fatalf("length 0 = %v, want true", value)
	}
}

func TestSleepTimerFiresReturnsTrue(t *testing.T) {
	orig := timeAfter
	timeAfter = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time)
		close(ch)
		return ch
	}
	defer func() { timeAfter = orig }()

	value, err := (sleepFunc{}).Execute(context.Background(), sleepRT(), &sleepArgs{Length: 3600})
	if err != nil {
		t.Fatalf("timer path: %v", err)
	}
	if value != true {
		t.Fatalf("timer path = %v, want true", value)
	}
}

func TestSleepRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value, err := (sleepFunc{}).Execute(ctx, sleepRT(), &sleepArgs{Length: 3600})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx err = %v, want context.Canceled", err)
	}
	if value != nil {
		t.Fatalf("cancelled ctx value = %v, want nil", value)
	}
}

func TestSleepNegativeLengthMirrorsPythonValueError(t *testing.T) {
	value, err := (sleepFunc{}).Execute(context.Background(), sleepRT(), &sleepArgs{Length: -1})
	if err == nil || err.Error() != "sleep length must be non-negative" {
		t.Fatalf("negative length err = %v, want sleep length must be non-negative", err)
	}
	if value != nil {
		t.Fatalf("negative length value = %v, want nil", value)
	}
}
