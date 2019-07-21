package descriptor

import (
	"net"
	"reflect"
	"testing"
	"time"
)

//func TestFetchRouterStatusEntries(t *testing.T) {
//	var conn, err = textproto.Dial("tcp", "localhost:9054")
//	if err != nil {
//		t.Fatalf("dial error: %v", err)
//		return
//	}
//	defer conn.Close()
//
//	var controller = control.NewConn(conn)
//	if err = controller.Authenticate(""); err != nil {
//		t.Fatalf("authentication error: %v", err)
//	}
//
//	var entries []RouterStatusEntry
//	entries, err = FetchRouterStatusEntries(controller)
//	if entries == nil {
//		t.Error("failed to fetch router status entries")
//	}
//
//	if err != nil {
//		t.Errorf("error fetching router status entries: %v", err)
//	}
//
//	controller.Close()
//	conn.Close()
//}

func TestParseRouterStatusEntry(t *testing.T) {
	t.Parallel()

	var entry = "r seele AAoQ1DAR6kkoo19hBAX5K0QztNw QNpJa2dktdn8SvNo30v/2B6s5Ko 2018-08-03 07:40:21 67.161.31.147 9001 0\n" +
		"s Fast HSDir Running Stable V2Dir Valid\nw Bandwidth=27"
	var got, err = parseRouterStatusEntry(entry)
	if err != nil {
		t.Fatalf("failed to parse router status entry: %v", err)
	}

	var want = RouterStatusEntry{
		Nickname:    "seele",
		Fingerprint: "000A10D43011EA4928A35F610405F92B4433B4DC",
		Digest:      "40DA496B6764B5D9FC4AF368DF4BFFD81EACE4AA",
		Published:   time.Date(2018, 8, 03, 07, 40, 21, 0, time.UTC),
		Address:     net.ParseIP("67.161.31.147"),
		ORPort:      9001,
		DirPort:     0,
		Flags: RouterFlags{
			Fast:    true,
			HSDir:   true,
			Running: true,
			Stable:  true,
			V2Dir:   true,
			Valid:   true,
		},
		Bandwidth: 27,
	}

	if !reflect.DeepEqual(*got, want) {
		t.Errorf("Expected %v got %v", want, *got)
	}
}

func TestParseRouterStatusEntriesRaw(t *testing.T) {
	t.Parallel()

	t.Run("short input", func(t *testing.T) {
		t.Parallel()
		var input = "\nr seele AAoQ1DAR6kkoo19hBAX5K0QztNw QNpJa2dktdn8SvNo30v/2B6s5Ko 2018-08-03 07:40:21 67.161.31.147 9001 0\n" +
			"s Fast HSDir Running Stable V2Dir Valid\n" +
			"w Bandwidth=27\n" +
			"r PutoElQueLee293884 AAwffNL+oHO5EdyUoWAOwvEX3ws 5QplY/hILpnKQmaLY2a0XDQqWPc 2018-08-03 01:31:37 174.127.217.73 55554 0\n" +
			"s Fast HSDir Running Stable V2Dir Valid\n" +
			"w Bandwidth=7470\n" +
			"r CalyxInstitute14 ABG9JIWtRdmE7EFZyI/AZuXjMA4 eWJZzoxXGAIKVXpxz1CVX3Fmvm8 2018-08-02 23:07:12 162.247.74.201 443 80\n" +
			"s Exit Fast Guard HSDir Running Stable V2Dir Valid\n" +
			"w Bandwidth=15800\n" +
			"r UbuntuCore239 ACsCTiSjDxE5gvyxff4FtvOMDHk ZPuLd7UfaBkIzBno5zkv6tFeVm0 2018-08-03 08:10:55 95.236.11.166 40889 0\n" +
			"s Fast Running V2Dir Valid\n" +
			"w Bandwidth=14"
		var got, err = ParseRouterStatusEntriesRaw(input)
		if err != nil {
			t.Fatalf("failed to parse router status entries: %v", err)
		}

		var want = []RouterStatusEntry{
			{
				Nickname:    "seele",
				Fingerprint: "000A10D43011EA4928A35F610405F92B4433B4DC",
				Digest:      "40DA496B6764B5D9FC4AF368DF4BFFD81EACE4AA",
				Published:   time.Date(2018, 8, 03, 07, 40, 21, 0, time.UTC),
				Address:     net.ParseIP("67.161.31.147"),
				ORPort:      9001,
				DirPort:     0,
				Flags: RouterFlags{
					Fast:    true,
					HSDir:   true,
					Running: true,
					Stable:  true,
					V2Dir:   true,
					Valid:   true,
				},
				Bandwidth: 27,
			},
			{
				Nickname:    "PutoElQueLee293884",
				Fingerprint: "000C1F7CD2FEA073B911DC94A1600EC2F117DF0B",
				Digest:      "E50A6563F8482E99CA42668B6366B45C342A58F7",
				Published:   time.Date(2018, 8, 03, 01, 31, 37, 0, time.UTC),
				Address:     net.ParseIP("174.127.217.73"),
				ORPort:      55554,
				DirPort:     0,
				Flags: RouterFlags{
					Fast:    true,
					HSDir:   true,
					Running: true,
					Stable:  true,
					V2Dir:   true,
					Valid:   true,
				},
				Bandwidth: 7470,
			},
			{
				Nickname:    "CalyxInstitute14",
				Fingerprint: "0011BD2485AD45D984EC4159C88FC066E5E3300E",
				Digest:      "796259CE8C5718020A557A71CF50955F7166BE6F",
				Published:   time.Date(2018, 8, 02, 23, 07, 12, 0, time.UTC),
				Address:     net.ParseIP("162.247.74.201"),
				ORPort:      443,
				DirPort:     80,
				Flags: RouterFlags{
					Exit:    true,
					Fast:    true,
					Guard:   true,
					HSDir:   true,
					Running: true,
					Stable:  true,
					V2Dir:   true,
					Valid:   true,
				},
				Bandwidth: 15800,
			},
			{
				Nickname:    "UbuntuCore239",
				Fingerprint: "002B024E24A30F113982FCB17DFE05B6F38C0C79",
				Digest:      "64FB8B77B51F681908CC19E8E7392FEAD15E566D",
				Published:   time.Date(2018, 8, 3, 8, 10, 55, 0, time.UTC),
				Address:     net.ParseIP("95.236.11.166"),
				ORPort:      40889,
				DirPort:     0,
				Flags: RouterFlags{
					Fast:    true,
					Running: true,
					V2Dir:   true,
					Valid:   true,
				},
				Bandwidth: 14,
			},
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("want %v, got %v", want, got)
		}
	})

	t.Run("long input", func(t *testing.T) {
		t.Parallel()
		var got, err = ParseRouterStatusEntriesRaw(testRouterStatusEntriesRaw)
		if err != nil {
			t.Fatalf("failed to parse router status entries: %v", err)
		}

		if len(got) == 0 {
			t.Errorf("failed to parse router status entries correctly, length of returned entries should not be 0")
		}
	})
}

func TestParseFlags(t *testing.T) {
	t.Parallel()

	var got = parseFlags([]string{"Fast", "HSDir", "Running", "Stable", "V2Dir", "Valid"})
	var want = RouterFlags{
		Fast:    true,
		HSDir:   true,
		Running: true,
		Stable:  true,
		V2Dir:   true,
		Valid:   true,
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v, got %v", want, got)
	}
}
