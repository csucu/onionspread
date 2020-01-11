package descriptor

import (
	"fmt"
	"testing"
)

func TestParseHiddenServiceDescriptorV3(t *testing.T) {
	t.Parallel()

	var got, err = ParseHiddenServiceDescriptorV3(testV3DescriptorRaw)
	if err != nil {
		t.Fatalf("failed to parse hidden service descriptor: %v", err)
	}

	fmt.Printf("desc: %#v", got)
}
