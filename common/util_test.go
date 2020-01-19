package common

import (
	"crypto/rsa"
	"encoding/base32"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

var rsaKey *rsa.PublicKey

func TestMain(m *testing.M) {
	var err error
	rsaKey, _, err = LoadKeysFromFile("../testdata/rsaKey")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestBase64ToHex(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
		want  string
		err   error
	}{
		{
			"success",
			"g55eugbqhviysu7bi4qzjcru5r4q7wxb",
			"839E5EBA06EA86F8B2B2EEDB8B8AB38DCAEEE6BE2AEF0C5B",
			nil,
		},
		{
			"success",
			"YWJjZGVmZw==",
			"61626364656667",
			nil,
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Base64ToHex(tt.input)
			if !reflect.DeepEqual(err, tt.err) {
				t.Errorf("expected %v got %v", tt.err, got)
			}

			if got != tt.want {
				t.Errorf("expected %s got %s", tt.want, got)
			}
		})
	}
}

func TestCalculateDescriptorID(t *testing.T) {
	permID, err := base32.StdEncoding.DecodeString(strings.ToUpper("facebookcorewwwi"))
	if err != nil {
		t.Fatalf("failed to calculate permanent id: %v", err)
	}

	got, err := CalculateDescriptorID(permID, 1435229421, 0, 0, "")
	if err != nil {
		t.Fatalf("failed to calculate descriptor id: %v", err)
	}

	if want := []byte("J3ZUU5O2DY5OLOD2HY74OJP3SHG24LZP"); !reflect.DeepEqual(want, got) {
		t.Errorf("expected %v got %v", want, got)
	}
}

func TestGetTimePeriod(t *testing.T) {
	got := getTimePeriod(1435229421, 0, []byte{40, 4, 64, 185, 202, 19, 162, 75, 90, 200}) // serviceID Bytes for "facebookcorewwwi"

	if want := int64(16611); want != got {
		t.Errorf("expected %v got %v", want, got)
	}
}

func TestGetSecretIDPartBytes(t *testing.T) {
	got := getSecretID([]byte{40, 4, 64, 185, 202, 19, 162, 75, 90, 200}, 1435229421, "", 0)
	want := []byte{160, 216, 228, 236, 154, 194, 138, 255, 237, 79, 168, 40, 232, 114, 124, 127, 212, 171, 73, 48}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("expected %v got %v", want, got)
	}
}

func TestLoadKeysFromFile(t *testing.T) {
	_, _, err := LoadKeysFromFile("../testdata/rsaKey")
	if err != nil {
		t.Fatalf("failed to load public key from file: %v", err)
	}
}

func TestCalculatePermanentID(t *testing.T) {
	got, err := CalculatePermanentID(*rsaKey)
	if err != nil {
		t.Errorf("failed to calculate permanent id: %v", err)
	}

	if want := []byte{248, 166, 21, 165, 230, 82, 1, 128, 34, 96}; !reflect.DeepEqual(want, got) {
		t.Errorf("expected %v got %v", want, got)
	}
}

func TestCalculateOnionAddress(t *testing.T) {
	want := "7ctbljpgkiayaita"
	if got := CalculateOnionAddress([]byte{248, 166, 21, 165, 230, 82, 1, 128, 34, 96}); got != want {
		t.Errorf("expected %v got %v", want, got)
	}
}

func TestDescriptorIDValidUntil(t *testing.T) {
	permID, err := CalculatePermanentID(*rsaKey)
	if err != nil {
		t.Fatalf("failed to calculate permanent id: %v", err)
	}

	if got := DescriptorIDValidUntil(permID, 1435229421); got != 50079 {
		t.Errorf("want %v got %v", 50079, got)
	}
}
