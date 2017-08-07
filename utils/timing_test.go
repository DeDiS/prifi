package timing

import (
	"strings"
	"testing"
	"time"
)

type TestOutput struct {
	Expected string
	test     *testing.T
}

func (t TestOutput) Print(msg string) {
	if !strings.HasPrefix(msg, t.Expected) {
		t.test.Errorf("Unexpected output : %s instead of %s", msg, t.Expected)
	}
}

func TestTiming(t *testing.T) {
	to := TestOutput{
		"WARNING: starting a measure that already exists with name: test (nothing will happen)",
		t,
	}

	SetOutputInterface(&to)

	StartMeasure("test")
	StartMeasure("test")

	time.Sleep(1 * time.Millisecond)

	to.Expected = "Measured time for test: "
	ret := StopMeasure("test")

	if ret < 1*time.Millisecond || ret > 1*time.Millisecond+500*time.Microsecond {
		t.Errorf("Invalid time measurment: %v", ret)
	}

	to.Expected = "WARNING: stopping a measure that was not started with name: test"
	v := StopMeasure("test")

	if v != 0 {
		t.Errorf("Invalid return value")
	}
}
