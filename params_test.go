package oauth2server_test

import (
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestParseSpaceSeparatedParameter_ReturnsSliceWithValues(t *testing.T) {
	result := oauth2server.ParseSpaceSeparatedParameter("\tone two    three ")
	expected := []string{"one", "two", "three"}

	if len(result) != 3 {
		t.Fatalf("expected a result slice with a length of 3, got %d", len(result))
	}
	for i, val := range result {
		if val != expected[i] {
			t.Errorf("result[%d] != %q: %q", i, expected[i], val)
		}
	}
}

func TestParseSpaceSeparatedParameter_EmptryStringReturnsNil(t *testing.T) {
	result := oauth2server.ParseSpaceSeparatedParameter("")

	if result != nil {
		t.Errorf("expected a nil result for an empty string: %#v", result)
	}
}

func TestParseSpaceSeparatedParameter_SpacesOnlyStringReturnsNil(t *testing.T) {
	result := oauth2server.ParseSpaceSeparatedParameter("\t ")

	if result != nil {
		t.Errorf("expected a nil result for a string with only spaces: %#v", result)
	}
}
