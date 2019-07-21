package onion

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/csucu/onionspread/common"
	"github.com/csucu/onionspread/descriptor"
)

func TestHSDirFetcher_update(t *testing.T) {
	t.Parallel()

	var logger = common.NewNopLogger()

	var testCases = []struct {
		name       string
		controller IController

		expectedHSDirs []descriptor.RouterStatusEntry
		expectedErr    error
	}{
		{
			"OK",
			&MockController{
				ReturnedRouterStatusEntries: []descriptor.RouterStatusEntry{
					{
						Nickname: "entry1",
						Flags: descriptor.RouterFlags{
							HSDir: true,
						},
					},
					{
						Nickname: "entry2",
						Flags:    descriptor.RouterFlags{},
					},
					{
						Nickname: "entry3",
						Flags: descriptor.RouterFlags{
							HSDir: true,
						},
					},
				},
				ReturnedErr: nil,
			},
			[]descriptor.RouterStatusEntry{
				{
					Nickname: "entry1",
					Flags: descriptor.RouterFlags{
						HSDir: true,
					},
				},
				{
					Nickname: "entry3",
					Flags: descriptor.RouterFlags{
						HSDir: true,
					},
				},
			},
			nil,
		},
		{
			"Failure fetching router status entries",
			&MockController{
				ReturnedErr: errors.New("test error"),
			},
			nil,
			errors.New("test error"),
		},
		{
			"nothing returned back",
			&MockController{},
			nil,
			errors.New("failed to fetch router status entries"),
		},
	}

	for _, testCase := range testCases {
		var tt = testCase
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var hsdirFetcher = NewHSDirFetcher(tt.controller, logger)
			if err := hsdirFetcher.update(); !reflect.DeepEqual(err, tt.expectedErr) {
				t.Errorf("expected %v got %v", tt.expectedErr, err)
			}

			if !reflect.DeepEqual(hsdirFetcher.hsDirs, tt.expectedHSDirs) {
				t.Errorf("expected %#v got error %#v", tt.expectedHSDirs, hsdirFetcher.hsDirs)
			}
		})
	}
}

func TestCalculateResponsibleHSDirs(t *testing.T) {
	t.Parallel()

	var controller = &MockController{
		ReturnedRouterStatusEntries: routerStatusEntries,
	}

	var hsdirFetcher = NewHSDirFetcher(controller, common.NewNopLogger())
	if err := hsdirFetcher.update(); err != nil {
		t.Fatalf("failed to update hsdir fetcher: %v", err)
	}

	var testCases = []struct {
		name  string
		input string

		want    []descriptor.RouterStatusEntry
		wantErr error
	}{
		{
			"success - mid slice",
			"AHF3RQU224ATC5XYHH35JTWXFLIUFB7H",
			[]descriptor.RouterStatusEntry{
				{
					Nickname:    "mravenisko1",
					Fingerprint: "01D3B71F140FFEC3A0C1FE84A656AE7697971EA4",
					Digest:      "8A791D5861C37BA4A89089D529B8BD3CE1699EAF",
					Published:   time.Date(2018, 8, 03, 06, 41, 40, 0, time.UTC),
					Address:     net.ParseIP("46.229.237.53"),
					ORPort:      9100,
					DirPort:     9101,
					Flags: descriptor.RouterFlags{
						Fast:    true,
						Guard:   true,
						HSDir:   true,
						Stable:  true,
						Running: true,
						V2Dir:   true,
						Valid:   true,
					},
					Bandwidth: 12000,
				},
				{
					Nickname:    "aerona",
					Fingerprint: "01E79D11DAF1B2F522CED15F3304C37656F98C7E",
					Digest:      "9940982AB8A3947F8A3476A7FB3D14A292C7BD12",
					Published:   time.Date(2018, 8, 03, 03, 56, 31, 0, time.UTC),
					Address:     net.ParseIP("145.239.72.73"),
					ORPort:      9001,
					DirPort:     9030,
					Flags: descriptor.RouterFlags{
						Fast:    true,
						Guard:   true,
						HSDir:   true,
						Stable:  true,
						Running: true,
						V2Dir:   true,
						Valid:   true,
					},
					Bandwidth: 15900,
				},
				{
					Nickname:    "bauruine56",
					Fingerprint: "021047C51A57254D263DDB8B9277CA1C286D600E",
					Digest:      "50DCB776195FE2008CC062A752A5B1DDDBE2A52D",
					Published:   time.Date(2018, 8, 02, 19, 0, 2, 0, time.UTC),
					Address:     net.ParseIP("94.198.98.21"),
					ORPort:      443,
					DirPort:     80,
					Flags: descriptor.RouterFlags{
						Fast:    true,
						Guard:   true,
						HSDir:   true,
						Stable:  true,
						Running: true,
						V2Dir:   true,
						Valid:   true,
					},
					Bandwidth: 16400,
				},
			},
			nil,
		},
		{
			"success - slice end",
			"AAFBBVBQCHVESKFDL5QQIBPZFNCDHNG3",
			[]descriptor.RouterStatusEntry{
				{
					Nickname:    "seele",
					Fingerprint: "000A10D43011EA4928A35F610405F92B4433B4DC",
					Digest:      "40DA496B6764B5D9FC4AF368DF4BFFD81EACE4AA",
					Published:   time.Date(2018, 8, 03, 07, 40, 21, 0, time.UTC),
					Address:     net.ParseIP("67.161.31.147"),
					ORPort:      9001,
					DirPort:     0,
					Flags: descriptor.RouterFlags{
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
					Flags: descriptor.RouterFlags{
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
					Flags: descriptor.RouterFlags{
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
			},
			nil,
		},
		{
			"success - slice start",
			"A4FSOU4XTVI7MZKLGNU4P7VOBZQJHL46",
			[]descriptor.RouterStatusEntry{
				{
					Nickname:    "seele",
					Fingerprint: "000A10D43011EA4928A35F610405F92B4433B4DC",
					Digest:      "40DA496B6764B5D9FC4AF368DF4BFFD81EACE4AA",
					Published:   time.Date(2018, 8, 03, 07, 40, 21, 0, time.UTC),
					Address:     net.ParseIP("67.161.31.147"),
					ORPort:      9001,
					DirPort:     0,
					Flags: descriptor.RouterFlags{
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
					Flags: descriptor.RouterFlags{
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
					Flags: descriptor.RouterFlags{
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
			},
			nil,
		},
		{
			"failure - bad descriptor id",
			"rrrrrrrrrrrrrrrrrr",
			nil,
			errors.New("failed to decode descriptor id: illegal base32 data at input byte 0"),
		},
	}

	for _, tt := range testCases {
		var tt = tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got, err = hsdirFetcher.CalculateResponsibleHSDirs(tt.input)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
