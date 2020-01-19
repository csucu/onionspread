package onion

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/csucu/onionspread/common"
	"github.com/csucu/onionspread/descriptor"
)

var (
	routerStatusEntries    []descriptor.RouterStatusEntry
	publicKey              *rsa.PublicKey
	privateKey             *rsa.PrivateKey
	backendDescriptor1     *descriptor.HiddenServiceDescriptor
	backendDescriptor2     *descriptor.HiddenServiceDescriptor
	backendDescriptorLong1 *descriptor.HiddenServiceDescriptor
	backendDescriptorLong2 *descriptor.HiddenServiceDescriptor
)

func TestMain(m *testing.M) {
	routerStatusesBytes, err := ioutil.ReadFile("../testdata/routerStatusEntriesShort.txt")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	routerStatusEntries, err = descriptor.ParseRouterStatusEntriesRaw(string(routerStatusesBytes))
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	publicKey, privateKey, err = common.LoadKeysFromFile("../testdata/rsaKey")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	//Desc 1
	backendDescriptorRaw, err := ioutil.ReadFile("../testdata/desc.txt")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	backendDescriptor1, err = descriptor.ParseHiddenServiceDescriptor(string(backendDescriptorRaw))
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	backendDescriptorRaw, err = ioutil.ReadFile("../testdata/desc2.txt")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	backendDescriptor2, err = descriptor.ParseHiddenServiceDescriptor(string(backendDescriptorRaw))
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	backendDescriptorRaw, err = ioutil.ReadFile("../testdata/desc-long1.txt")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	backendDescriptorLong1, err = descriptor.ParseHiddenServiceDescriptor(string(backendDescriptorRaw))
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	backendDescriptorRaw, err = ioutil.ReadFile("../testdata/desc-long2.txt")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	backendDescriptorLong2, err = descriptor.ParseHiddenServiceDescriptor(string(backendDescriptorRaw))
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestDescriptorIDChangingSoon(t *testing.T) {
	t.Parallel()

	mockTime := &common.MockTimeProvider{}
	mockTime.Set(time.Date(2015, time.June, 25, 24, 0, 3, 4, time.UTC))

	var onion, err = NewOnion(nil, []string{}, publicKey, privateKey, nil, common.NewNopLogger(), mockTime, 0)
	if err != nil {
		t.Fatal("failed to create new onion")
	}

	if got := onion.descriptorIDChangingSoon(); got != true {
		t.Errorf("want true got false")
	}
}

func TestNotPublishedDescriptorRecently(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		lastPublishTime int64
		want            bool
	}{
		{
			"hasnt been published yet",
			0,
			true,
		},
		{
			"published recently",
			time.Now().Unix() - 3600,
			false,
		},
		{
			"published long ago",
			time.Now().Unix() - 4000,
			true,
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var onion = Onion{
				lastPublishTime: tt.lastPublishTime,
				publishInterval: 3600,
				logger:          common.NewNopLogger(),
				time:            common.NewTimeProvider(),
			}

			if got := onion.notPublishedDescriptorRecently(); got != tt.want {
				t.Errorf("want %v got %v", tt.want, got)
			}
		})
	}
}

func TestOnion_introductionPointsChanged(t *testing.T) {
	t.Parallel()

	logger := common.NewNopLogger()

	oldDescs := []descriptor.HiddenServiceDescriptor{
		{
			DescriptorID:          "oldDesc",
			IntroductionPointsRaw: "oldIntros",
			IntroductionPoints: []descriptor.IntroductionPoint{
				{
					Identifier: "testID",
				},
			},
		},
	}

	newDescs := []descriptor.HiddenServiceDescriptor{
		{
			DescriptorID:          "newDesc",
			IntroductionPointsRaw: "newIntros",
			IntroductionPoints: []descriptor.IntroductionPoint{
				{
					Identifier: "testID",
				},
			},
		},
	}

	testCases := []struct {
		name  string
		onion *Onion

		expectedResult        bool
		expectedErr           error
		expectedBackendOnions backendOnions
	}{
		{
			"Descriptors changed",
			&Onion{
				controller: &MockController{
					FetchedDescriptors: map[string]*descriptor.HiddenServiceDescriptor{
						"address": &newDescs[0],
					},
				},
				backendOnions: backendOnions{
					addresses:   []string{"address"},
					descriptors: oldDescs,
				},
				logger: logger,
			},
			true,
			nil,
			backendOnions{
				addresses:                       []string{"address"},
				descriptors:                     newDescs,
				totalNumberOfIntroductionPoints: 1,
				newDescriptorsAvailable:         true,
			},
		},
		{
			"Descriptors not changed",
			&Onion{
				controller: &MockController{
					FetchedDescriptors: map[string]*descriptor.HiddenServiceDescriptor{
						"address": &oldDescs[0],
					},
				},
				backendOnions: backendOnions{
					addresses:   []string{"address"},
					descriptors: oldDescs,
				},
				logger: logger,
			},
			false,
			nil,
			backendOnions{
				addresses:   []string{"address"},
				descriptors: oldDescs,
			},
		},
		{
			"No descriptors stored previously",
			&Onion{
				controller: &MockController{
					FetchedDescriptors: map[string]*descriptor.HiddenServiceDescriptor{
						"address": &newDescs[0],
					},
				},
				backendOnions: backendOnions{
					addresses: []string{"address"},
				},
				logger: logger,
			},
			true,
			nil,
			backendOnions{
				addresses:                       []string{"address"},
				descriptors:                     newDescs,
				totalNumberOfIntroductionPoints: 1,
				newDescriptorsAvailable:         true,
			},
		},
		{
			"fail - fetch error",
			&Onion{
				controller: &MockController{
					ReturnedErr: errors.New("test error"),
				},
				logger: logger,
				backendOnions: backendOnions{
					addresses: []string{"address"},
				},
			},
			false,
			errors.New("failed to fetch any descriptors"),
			backendOnions{
				addresses: []string{"address"},
			},
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.onion.introductionPointsChanged(context.Background())
			if !reflect.DeepEqual(err, tt.expectedErr) {
				t.Errorf("expected %v got %v", tt.expectedErr, err)
			}

			if got != tt.expectedResult {
				t.Errorf("expected %v got %v", tt.expectedResult, got)
			}

			if !reflect.DeepEqual(tt.onion.backendOnions, tt.expectedBackendOnions) {
				t.Errorf("expected %#v got %#v", tt.expectedBackendOnions, tt.onion.backendOnions)
			}
		})
	}
}

func TestOnion_fetchBackendDescriptors(t *testing.T) {
	t.Parallel()

	logger := common.NewNopLogger()

	testCases := []struct {
		name       string
		controller *MockController

		expectedDescs     []descriptor.HiddenServiceDescriptor
		expectedErr       error
		expectedIntrosLen int
	}{
		{
			"OK",
			&MockController{
				FetchedDescriptors: map[string]*descriptor.HiddenServiceDescriptor{
					"backend-1": {
						DescriptorID: "backend-1-desc-id",
						IntroductionPoints: []descriptor.IntroductionPoint{
							{
								Identifier: "8e2uej23ie2",
							},
						},
					},
					"backend-2": {
						DescriptorID: "backend-2-desc-id",
						IntroductionPoints: []descriptor.IntroductionPoint{
							{
								Identifier: "2323e323e23",
							},
						},
					},
					"backend-3": {
						DescriptorID: "backend-3-desc-id",
						IntroductionPoints: []descriptor.IntroductionPoint{
							{
								Identifier: "982ujn99j92",
							},
						},
					},
				},
			},
			[]descriptor.HiddenServiceDescriptor{
				{
					DescriptorID: "backend-1-desc-id",
					IntroductionPoints: []descriptor.IntroductionPoint{
						{
							Identifier: "8e2uej23ie2",
						},
					},
				},
				{
					DescriptorID: "backend-2-desc-id",
					IntroductionPoints: []descriptor.IntroductionPoint{
						{
							Identifier: "2323e323e23",
						},
					},
				},
				{
					DescriptorID: "backend-3-desc-id",
					IntroductionPoints: []descriptor.IntroductionPoint{
						{
							Identifier: "982ujn99j92",
						},
					},
				},
			},
			nil,
			3,
		},
		{
			"fetch failures",
			&MockController{
				ReturnedErr: errors.New("test error"),
			},
			nil,
			errors.New("failed to fetch any descriptors"),
			0,
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			onion, err := NewOnion(tt.controller, []string{"backend-1", "backend-2", "backend-3"}, publicKey, privateKey, nil, logger, common.NewTimeProvider(), 0)
			if err != nil {
				t.Fatal("failed to create new onion")
			}

			descs, introsLen, err := onion.fetchBackendDescriptors(context.Background())
			if !reflect.DeepEqual(err, tt.expectedErr) {
				t.Errorf("expected %v got %v", tt.expectedErr, err)
			}

			if introsLen != tt.expectedIntrosLen {
				t.Errorf("expected %v got %v", tt.expectedIntrosLen, introsLen)
			}

			if !reflect.DeepEqual(descs, tt.expectedDescs) {
				t.Errorf("expected %#v got %#v", tt.expectedDescs, descs)
			}
		})
	}
}

// Add tests with more backend descriptors
func TestOnion_singleDescriptorGenerateAndPublish(t *testing.T) {
	t.Parallel()

	logger := common.NewNopLogger()

	testCases := []struct {
		name               string
		controller         *MockController
		backendDescriptors []descriptor.HiddenServiceDescriptor
		privateKey         *rsa.PrivateKey

		expectedErr                   error
		expectedIntroductionPointsRaw string
	}{
		{
			"OK",
			&MockController{},
			[]descriptor.HiddenServiceDescriptor{*backendDescriptor1, *backendDescriptor2},
			privateKey,
			nil,
			"-----BEGIN MESSAGE-----\n" +
				"aW50cm9kdWN0aW9uLXBvaW50IDZ6bXpicXIyd2FsMnluemNuMnprMnBuZnZkdm9r\n" +
				"eGltCmlwLWFkZHJlc3MgOTEuMjIxLjExOS4zMwpvbmlvbi1wb3J0IDQ0Mwpvbmlv\n" +
				"bi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU4z\n" +
				"TEU4ZnVwa29YczlrRnVLL1Y2dlFRZkNicTRVclFWOURIck9sTHYwT1dsK1dSMnVH\n" +
				"MFE0LzAKOHhLL1YrZ2lyTHVlOGNybXNwOGg5U0p0WmlVRC9DaDFwQ21oMXRnUGgz\n" +
				"cUtPOHcwUTlMR21EdTNSSGt1ZkZRLwplYUQ0aDUxVzF4NWVtU2VPVitJbDFQL1BY\n" +
				"YUVxdWNMeWIrZVBYTHluTVVKeTc1Y2QrTm9aQWdNQkFBRT0KLS0tLS1FTkQgUlNB\n" +
				"IFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJM\n" +
				"SUMgS0VZLS0tLS0KTUlHSkFvR0JBSytpb0pIdXZOZTZJYUgvWlU5bk90WlhIbWFU\n" +
				"ci82RkNwZkUxcHFKbjEvdkJZdklCZUVxK205YgpjdUN5VEQvbzZ4Nld4UHFrNHU2\n" +
				"alRDelZRdHBoMit3dW5aOHJqVkUyYXdxNjZvVmZyMmhLUlp3UUtTT2pWTU1GCnNH\n" +
				"Z0VHeW1tMjVnL3pvdk5LZXh3cFArUWUzSDNmVW9HakVCeWVzUkV6RkhPZE1qdDI1\n" +
				"a3ZBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVj\n" +
				"dGlvbi1wb2ludCBzNXpvN25qdmhmNmppbGIyeGNhZTdtMjQ3NndxY2pieQppcC1h\n" +
				"ZGRyZXNzIDM3LjE1My4xLjEwCm9uaW9uLXBvcnQgOTAwMQpvbmlvbi1rZXkKLS0t\n" +
				"LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUthTTlkQzRoZDZx\n" +
				"bzVQVUcxcmJOTEZoMUxzWmozbGVxOHFRWGg2aVBYcDJQK2hoSFBQL0RId2kKUmFj\n" +
				"eFlaVG1JbWM4b09XSktNL01rVFNYdVd1Q0hQSDhkNE52M05Ed0h3anN0bEQxenFJ\n" +
				"S2xYemhydFNVNHBrUgpQckJrMWRLdjc3MHUvTC9Yemh0SDVCYldRMG9RMitYbno1\n" +
				"UG9JcEhMUzVORUVvUzJmeHpSQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBL\n" +
				"RVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0t\n" +
				"LS0KTUlHSkFvR0JBTDR2RFJNOFBIZWJPOHAvUFZKVVJ1T1J2VXpCZHhsZXJCd3pF\n" +
				"MWdyTmRQY1VuMW9vcVQ4eEhhTgp5L1dhME4wVEVjY0p4bnUxSkxsNXJXV05BNHNU\n" +
				"dm5GQk51eVRRK0FLU0x2REtmbWxDazVrYUdiaXBFVGRYNVhkCk1CUThQRHJlR3ZW\n" +
				"QlhEckhQcGtUcmtFVlREUFhUdlJ6REFyTW1MRHM4ayt4N2s5WGw0eXpBZ01CQUFF\n" +
				"PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2lu\n" +
				"dCBxcmZvdHN3cWltczZzdnBjeHlrc2N2cjNwaDdoYmZmeAppcC1hZGRyZXNzIDE5\n" +
				"Mi44Ny4yOC44Mgpvbmlvbi1wb3J0IDkwMDEKb25pb24ta2V5Ci0tLS0tQkVHSU4g\n" +
				"UlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNSlJ4ODJOblV4Y2VaME1ZM2ps\n" +
				"Nm4vZnNwWHpSMjNNbUxUS0R0QmZyQzVyTStrL1FnYWV5Z295Cm1HeXpGakRNOUxX\n" +
				"TUVTUkE3bStlUmZVeTBkaGN6V3dncEU2RXZ6WHdOZklYdER6NWF5c0FJZWhMbk9z\n" +
				"TlNRRHgKaTFPOUQzbVdkZVp6YzZEVGJ5VS85UDBPSTBIQUJQWDg4M29uMWdwYUNX\n" +
				"bVZDV1ZlZ1FkekFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
				"c2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pB\n" +
				"b0dCQUw1Y2NjVkZkcFlvWklpOGZubXdZTDVzTC9pQkVVbldXbDJsUHhZZmhMM1ZE\n" +
				"KzIxQU1kL3hpZkIKSDNWdFQ0bHFtbVdOckEwa2dRU1BJaUVCOU5VZUh4NDBROGlm\n" +
				"eklMYnNjUnJ5NmdIaFViZk0yT2tqc29TMm9kTwphZmczZy9PYno4aEVRNDVQQ2V6\n" +
				"Mm0vRVFyNFJpaU5uZGdQQ1B0S3Jia25iTW41a3lOSWRuQWdNQkFBRT0KLS0tLS1F\n" +
				"TkQgUlNBIFBVQkxJQyBLRVktLS0tLQoKaW50cm9kdWN0aW9uLXBvaW50IG9jZ2Fr\n" +
				"dXR4MjNhcnFja2hqYmIyZTZjemJnNmxtZHNtCmlwLWFkZHJlc3MgMTg1LjIyNS4x\n" +
				"Ny4xNTEKb25pb24tcG9ydCA5MDAxCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQ\n" +
				"VUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTDZqSWRFa3BNaDRxU0ZoQjBnVmVHVmJF\n" +
				"NlRkbE04WUl4dmt5SWNCd1BONW4wa0dMTlcrenJnOApvQUp1UzhVY0d6cEFDUzlS\n" +
				"Nnd5Q2RCVm1kZG5zNDRDV0Z4bWtXK3dVOG9LZjhZenJJTUJCd25tampMbWEwZ2JQ\n" +
				"Cm1jY01TMjdHbndnSnhjeVhjVEpXL3JxN0RmczR3cVprcWF3ajRNRGtXaUpRUCtE\n" +
				"S2g5aTNBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZp\n" +
				"Y2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFP\n" +
				"SUVyQVYyRDVncFhtbUp4MS9URlR0eUNrcnBnOVMydUJtY1VmTnhzK0hmazRIYzQ4\n" +
				"MUE1VzJNClB0cXE5bmVUUzlOZW50WG12cyszM1k0cWp5cFIzZEY0UWx1bVY0cWtv\n" +
				"Z01hd1ZiWEs2MTN4OHU0c0FsaDZic3AKVER4bkRFcWZmLzNJUWl6VWc5VEh6Q3Zs\n" +
				"WmhoUE1ZSmtpdXBGTmJ0U1MveFBqdWcxWVJDRkFnTUJBQUU9Ci0tLS0tRU5EIFJT\n" +
				"QSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IGZ0c2UzNXBvNWpo\n" +
				"dmVwZWVkY29xdHI0Y3h1bTZhMnJ3CmlwLWFkZHJlc3MgMzcuMTIwLjE3Mi4yNDIK\n" +
				"b25pb24tcG9ydCA5MDAxCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMg\n" +
				"S0VZLS0tLS0KTUlHSkFvR0JBTysvMjZWM29YTitta2ZkTEo3MVMzNjBKOVZvSVZD\n" +
				"NCs1UitMelJiOHVHU25XU2lyd2dYV0FWaQpaTFlxUmNpMzR6T0pPcTdGeTBRcTFw\n" +
				"a3FTU2dqTEdDc3ptR2R2WllCeFBKMHdQV0oyZUxSRkNSVnhhdHNqQ1JOCkg1Z1l6\n" +
				"bzkzVUFTb1UzMFFFVFpTLzBEWWxQOWtISmRHU1RVUlIzanljVVZ6L3V1UDRkalZB\n" +
				"Z01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5\n" +
				"Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNM0NxM1Zu\n" +
				"SjVjKzlBM2YxK0k0NEkwRE9rTVBRME5yZU1JeFdCZCtoQ0k1ZS9ua0VkYjlBL1dB\n" +
				"Ck12VnAzS0RhQVZaTUNWZUphMWhBR0JRNHJCcE1IaCs4Uk9xQS9UdDhyL2V5dzR2\n" +
				"cHh0d1cwb0lnRXl3MkNvRU8KSUN0dkRuQ1N6RTdYQUtmazFiU0twZWQ5T2NhajMx\n" +
				"dVBQUURvdWVkNlJYaU5zVlVYaFR6ekFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJM\n" +
				"SUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IHUydmlpZ3JieW1rbXF5ZHV3\n" +
				"dmRzM3pqY2xranBuZHgzCmlwLWFkZHJlc3MgOTEuNjYuNTAuODEKb25pb24tcG9y\n" +
				"dCA5MDAyCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
				"TUlHSkFvR0JBTHd6NzBRT2V3dHVBWFJxR242Z2ptNmVKSlJSWTBaNHYrRTJ2MDZu\n" +
				"RGFramNJU2xvVjJSenU4VgpqSmpkaUdmOFJKbnRtb09jTkRsczhFekRPUW1IWnhN\n" +
				"bERibHZrMzk3RjJsL1JKMXU3d0hFNXgvOE04bzE1MXVxCkpTUk1PVkNoZjlORzRJ\n" +
				"Mk5ZN25xeUxwUnNHMHc0UjJSSi9VU2gvM24zd2NUS2lnc1ZBU0RBZ01CQUFFPQot\n" +
				"LS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVH\n" +
				"SU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMcjZnbG8xUVlxQThzRDNq\n" +
				"U0dJNm5RdnJmVC9nYjNCSTlyUC9xcDQvaXJTcHZMWExYQVE5REVhCjExQ256a1Yy\n" +
				"dmh3STkySEovMHNWanBPa0s5R216VGt4aXhQNklBMGZQeWc2SmZLNzJOZ3B4TCtN\n" +
				"eGI2VXRLSWIKOFZKR2NYb1NZejhIT2M2RzY0eTArc0hsMXRGSFIrY0NxQU1jUnor\n" +
				"VVBDMzZIbTNJNDZEekFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0t\n" +
				"LS0KCg==\n" +
				"-----END MESSAGE-----\n",
		},
		{
			"failure generating descriptor",
			&MockController{},
			[]descriptor.HiddenServiceDescriptor{*backendDescriptor1, *backendDescriptor2},
			func() *rsa.PrivateKey {
				pri := *privateKey
				pri.E = 0
				return &pri
			}(),
			errors.New("failed to generate descriptor: failed to sign descriptor: rsa: internal error"),
			"",
		},
		{
			"failure posting descriptor",
			&MockController{
				ReturnedErr: errors.New("test error"),
			},
			[]descriptor.HiddenServiceDescriptor{*backendDescriptor1, *backendDescriptor2},
			privateKey,
			errors.New("failed to post descriptor: test error"),
			"",
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			onion, err := NewOnion(tt.controller, []string{}, publicKey, tt.privateKey, nil, logger, common.NewTimeProvider(), 0)
			if err != nil {
				t.Fatal("failed to create new onion")
			}

			err = onion.singleDescriptorGenerateAndPublish(tt.backendDescriptors)
			if !reflect.DeepEqual(err, tt.expectedErr) {
				t.Errorf("expected %v got %v", tt.expectedErr, err)
			}

			parsedDescriptor, err := descriptor.ParseHiddenServiceDescriptor(tt.controller.PostedDescriptor)
			if err != nil {
				t.Fatal("failed to parse descriptor")
			}

			if parsedDescriptor.IntroductionPointsRaw != tt.expectedIntroductionPointsRaw {
				t.Errorf("expected %v got %v", tt.expectedIntroductionPointsRaw, parsedDescriptor.IntroductionPointsRaw)
			}
		})
	}
}

func TestOnion_multiDescriptorGenerateAndPublish(t *testing.T) {
	t.Parallel()

	logger := common.NewNopLogger()
	hsdirFetcher := &MockHSDirFetcher{
		returnResponsibleHSdirsMap: map[string][]descriptor.RouterStatusEntry{
			"S43ALCS3QYEYC4XDY7TH2ZF7C7KVRXSE": {
				{
					Nickname:    "hsdir1",
					Fingerprint: "hsdir1-fingerprint",
				},
				{
					Nickname:    "hsdir2",
					Fingerprint: "hsdir2-fingerprint",
				},
				{
					Nickname:    "hsdir3",
					Fingerprint: "hsdir3-fingerprint",
				},
			},
			"K4F6ZHKHI5XOXKYJZT3AFGLR5N5POUVC": {
				{
					Nickname:    "hsdir4",
					Fingerprint: "hsdir4-fingerprint",
				},
				{
					Nickname:    "hsdir5",
					Fingerprint: "hsdir5-fingerprint",
				},
				{
					Nickname:    "hsdir6",
					Fingerprint: "hsdir6-fingerprint",
				},
			},
		},
	}

	mockTime := &common.MockTimeProvider{}
	mockTime.Set(time.Date(2019, time.January, 10, 1, 2, 3, 4, time.UTC))

	testCases := []struct {
		name               string
		controller         *MockController
		hsdirFetcher       *MockHSDirFetcher
		backendDescriptors []descriptor.HiddenServiceDescriptor
		privateKey         *rsa.PrivateKey

		expectedErr                  error
		expectedDescriptorsIntrosRaw map[string]string
	}{
		{
			"OK",
			&MockController{},
			hsdirFetcher,
			[]descriptor.HiddenServiceDescriptor{*backendDescriptorLong1, *backendDescriptorLong2},
			privateKey,
			nil,
			map[string]string{
				"hsdir1-fingerprint": "-----BEGIN MESSAGE-----\n" +
					"aW50cm9kdWN0aW9uLXBvaW50IHIyM3NmNnEyNWhvNmRla2x5aXA2dWl1YnR2ZzZ0\n" +
					"aG51CmlwLWFkZHJlc3MgMTk1LjE4OS45Ni4xNDgKb25pb24tcG9ydCA0NDMKb25p\n" +
					"b24ta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFN\n" +
					"Qk94SStacU1BVTlkcGNLaUxyNUlaMGc5RThPaFUvaEFvMlZzdnBKOFJpb2JNRFFK\n" +
					"RHl2NUpjClFFbTZ5OW1DQ2lCWGM2UFRGeHhBMnd0b1hRWXhRQ0pEWTdwMkt6SHdm\n" +
					"KzJaZjZ6QTlMYWJUV2diNjVnZDUxVmsKelpaYWI5aTFwY2RBaGdZR1E1M3NvM25v\n" +
					"K2J6WDE2RWpPUEJiUzFIN0hzbjJjcktPUTNQM0FnTUJBQUU9Ci0tLS0tRU5EIFJT\n" +
					"QSBQVUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVC\n" +
					"TElDIEtFWS0tLS0tCk1JR0pBb0dCQU5NU2dheVBCUE5jemZueWhkbXUvZk1Rb3Zl\n" +
					"bzlRZGk2WjV0enFvOWtNd1lnYlNxdUNxa1p3azgKOGI2eFhFOUw0MWx3a2tMWWRh\n" +
					"SVh2SEhGc0hsaWFHOGU3MVo4RGlDTnFUaWloRlFZdjc3b2FTMDJ0Nk92MzN0TwpN\n" +
					"QU1uZEI5MG5tN0JsemhFK0gwOGU1NFJPeGJBaGhBTUpVQTNYbEJROHBGQS9tQTgz\n" +
					"NUl2QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1\n" +
					"Y3Rpb24tcG9pbnQgM2dpa3J0ejV6N2xudGhxdHdpeW5kbjRpaWhrZm5kc2sKaXAt\n" +
					"YWRkcmVzcyAxNDEuNzAuMTI1LjE1Cm9uaW9uLXBvcnQgOTAwMQpvbmlvbi1rZXkK\n" +
					"LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUtjTlZ5cDA3\n" +
					"ZHBIUFBFakd2eGRvN3FjS1YxakxvNVBrT0tnTFlUUkJrZ2FxV2xLWThmYzJFTHIK\n" +
					"UW1pNFViaUNCR2dxanFuRWZDVnVRcHVtSTgrZkZTVjRQWUtyeXJ6VHNyNSsvV1ht\n" +
					"ZUY1TzVtTWphSFZxdVU1cQppaXNabGZ1T3B2Nnk1R3d5QUYwVHBNclFITm1zcTF3\n" +
					"UW5HYmdPTFFFa3N0SS94TFdCUnVQQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJ\n" +
					"QyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZ\n" +
					"LS0tLS0KTUlHSkFvR0JBTWNUelU5RDZkTmlqT3FMYUx2ZjFUN1dUNVJ4amZRN0Zp\n" +
					"ZlJoUXphVWs5RU5ZOTlrdlBmK296dwpPckluT21pRnlXYU9ya01CSDE4NXVIZE1V\n" +
					"bU55S0RMSlN6SE1MU2I4UmFiSmZuamd3ZUpPZGZ5UTJwUDRwWW9HCmRiZ2ozN1V6\n" +
					"MUg4UzkwanROejRGNUN1bjlXUEt0eDV6MkRyWXBCSlNiT0RmeVZKODZXWFZBZ01C\n" +
					"QUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1w\n" +
					"b2ludCB6bzVlYjU2ejZrY3BpNnJlaDNybWJhcGptMmJoaWhqYwppcC1hZGRyZXNz\n" +
					"IDE3Ni45LjM5LjE5Ngpvbmlvbi1wb3J0IDkwMDEKb25pb24ta2V5Ci0tLS0tQkVH\n" +
					"SU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNVEJvSG5hcWNLUkpseTFi\n" +
					"VVZLRVZRMk9IZ2N0Z1ZxSWg5YW9DVVI0ckd2ZXpwZ0tVeFIzeTJBCjBubnNiUVRZ\n" +
					"cFJtdXErSU04TmdibUZ0VHVXYzFZajdUcldnVEYzNXUvNkpubG41ZjJ5MGpvUTNJ\n" +
					"K0FubFlUVDAKMWIzbnEwVUV6ZmRnTTJUZmQ2Y21lR0o3UHRIb09PaXZURmdUdVlM\n" +
					"N1FUQ2ZTcTkvRXAwL0FnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1J\n" +
					"R0pBb0dCQUo1dWJoUTBTbGlJZzkrYjlzN1Q3b3hEUlE4aXJIaVJiSHlNcVFsZ08v\n" +
					"V3B0VUcwaWhFUWZlSjEKaTYvRDJjU3o5dlhpWjFoRkF1S0lFTVpKQmRHdW5qamFn\n" +
					"Sm5welpJWXhkcldQWkpPN0NiUDFCVzBRYnlZKzFvWAoxS3lnNzB3cmx5RVR6QjI4\n" +
					"RE9tL3UwT2gvaXU0OTkxZnhlcjhXWkJTR09DNlo0azdJa0FqQWdNQkFBRT0KLS0t\n" +
					"LS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQgeG9i\n" +
					"dDMyNGlmbDRremFnY3l6NjNmbGNwb2FqbXdlbHIKaXAtYWRkcmVzcyAzNy4xODcu\n" +
					"OTYuNzgKb25pb24tcG9ydCA5MDAxCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQ\n" +
					"VUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTVZKWThHMlM1WVp0R1cvVFQwdk1YV1dq\n" +
					"emd1YXZvOTNpZkllTUc1UGdBY3BGdXp1SlJkQk9MaQpnTGJybFN6UUNvK0lYaENq\n" +
					"ZTlsNXdzOGV6Ri9oVEptN0c1Umd0RzBLbjluUnEwRi9LWU1oajZEMjZsYWF1RjJN\n" +
					"CjBISTZsaVBndHo5R2FGem1zVDhSRXRaZkcwZE8ra1loeU14Wk9jeVdxL2M3Yjly\n" +
					"cWUzbzNBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZp\n" +
					"Y2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFO\n" +
					"RjNOK0RndzNPbHcxbUhPOUpPZDJZanMwOU9lSlZNQjlsQkM3NUNHT3dzQTlLb2ow\n" +
					"cjFUZlE0CnprdWpzWGJ5OW9vZEFlemwzTDlBaXpGZXkvZEpyTi83Rml0K3hXWHVN\n" +
					"aUlNOG5JekNnbEY3Z3VvMklvbXBKYnAKQ09XRWNVNGNtTEpNRlk1S3NvUTVPNDZB\n" +
					"MHNLVDZiWmk4RjdYcnhsd1JUVHBWTnJNMDRpakFnTUJBQUU9Ci0tLS0tRU5EIFJT\n" +
					"QSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IHlxa3BmZDZzeDNh\n" +
					"dmttYmVmZ250ZHZoaGUyN2xyejRpCmlwLWFkZHJlc3MgMTg4LjEzOC4xMTIuNjAK\n" +
					"b25pb24tcG9ydCAxNTIxCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMg\n" +
					"S0VZLS0tLS0KTUlHSkFvR0JBUEVVN1lCWTJqUVFEbmx1SVowRlhJUHZ3eHgreUpL\n" +
					"K1NtN1g1ekNPb0NTQkpRSXRUWTVQeWtZZgptOGQyNzlpQ2NPNk9FZFJFOW54SE5L\n" +
					"UUFiOFVQWjRWSWt4SU1QS0gyS25SVHhQL0JseGR0ditidStzSEhLRVJxCjJVZWRV\n" +
					"Tk9VOW1xQzk5M216WEI3ejhPeXp1QVBsNTV5Y3hBdmFaNWZ3TlV3Sy92RnlZcnRB\n" +
					"Z01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5\n" +
					"Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMUVlXcUtJ\n" +
					"ZkZ0V09LSmZreFc3L1NxM2ZMaWlsM1RoUkpxa241cFQvTjA2ckNQQTV5VDk0WE44\n" +
					"ClNDblNJQ3Jhb2t4cXI2OXJxbzloRDlxYTVnczhoUnFoQlROdFJiN3RScWdKZ09Y\n" +
					"aURSQUZ6eFlad3ZhWk9taWcKTWZHUGs4Tk11UldXYnluV2ZHcVZVam9MNHcvQStp\n" +
					"aUdDRVhGTklYY3JyMTdFMytRZHhzVkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJM\n" +
					"SUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IDM1NWtjM3EybWEzNGw3ZjNq\n" +
					"eHd1Nm90bTJqcm11bjR6CmlwLWFkZHJlc3MgMTk1LjE1NC4yNTMuMjI2Cm9uaW9u\n" +
					"LXBvcnQgNDQzCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0KTUlHSkFvR0JBTUI3WFUvMkJJaGJDSktNb1NtUnlhNjZnRXNpcHFDakxHUUcx\n" +
					"T2xTb1lveFUwNTBYRTZ5VnBhYgpvT1d4eVYwT2xLNXNJSjNaM2FXM3Qra1FUOGZq\n" +
					"NHFwQjV6ZWg2V0dSVmN0bStHNkVScEZkVFFHMkdTMjg5VVE1Ci93aDk2Nm5xSVhz\n" +
					"SnJWNzBKa1BMOUVsMllRZm9NMG5oSHlJclBhN1lRNVNqSEtIUTZTRnRBZ01CQUFF\n" +
					"PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0t\n" +
					"QkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFLUmVxQjhKYmhpRjZy\n" +
					"cW9NVk1xODlEeHlRN1dBMDI1aTF5VEFHQkM5bFR2RjZYWldLQmpzU0ZpCmo1SDUw\n" +
					"KzBLS284eU1GNWRUYUd2d01XVllMNzRFNVlQOTU3Qi81bXJPOFowc3RERHNEK3FM\n" +
					"dmdCRjdUWmpxOGEKOFFjQXVmV3d1Y3hqUU5wK1lRdzFuamtIOEpEdjBsb3lFY0dH\n" +
					"QVk3T3pUUUkvM3ZGaklaTEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZ\n" +
					"LS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IGl5b3c1aWt6bTNkN3RnMmQybjVueWVs\n" +
					"bGxvaGVwdWpxCmlwLWFkZHJlc3MgNTEuMjU0LjQ1LjQzCm9uaW9uLXBvcnQgOTAw\n" +
					"MQpvbmlvbi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pB\n" +
					"b0dCQUs2NExRRWhrRkhybitERHhUS01kNGxZR1FHMjVPWHpQNk5ldEJzVk1mNHQ1\n" +
					"Q0lqT1VaWXU1SDcKU21oYVJBRitMOE5PbTlJVmRSZVhpK2srL0thdnRwb2xJVU04\n" +
					"VEhQMm9ZMk5yOUlHanEvT0pZOUtwSllQMTlKbgpndDI2cHEzSFpzWDA2ZWE2emdm\n" +
					"TTc5VllucmZ5QjNPN2VJUUNtTkhIWGZoSGhNQmtVb0JmQWdNQkFBRT0KLS0tLS1F\n" +
					"TkQgUlNBIFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJT\n" +
					"QSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTU5FM1JZZUFhNmpQYjlsWldDZUVD\n" +
					"M2liSWVNR3k5MFZwcE13aHBVU1FpVmMwazFENU8xWjZ4Kwp0TzFSVC8wZ3ZZdWdm\n" +
					"dGcyNUl0OE0yamVQRWNRVk91NlJGazZzeGpjeVhERnA1aytVdVRFSnhRcU45akhy\n" +
					"Z0ZwCkoxZy9IUkxPZHV1UEowTXczWGE1OFVOc25mdEdueGhXRlVnQWlEN3UrcUxt\n" +
					"Y1BTMjBrSUJBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmlu\n" +
					"dHJvZHVjdGlvbi1wb2ludCBkb3AyejRzNmM3amc0bWQ2dTdoMnB2Y3Z3ZmNsYW14\n" +
					"ZgppcC1hZGRyZXNzIDgyLjk0LjI1MS4yMjcKb25pb24tcG9ydCA0NDMKb25pb24t\n" +
					"a2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMR0pt\n" +
					"MG5SSWZzQ1N5Qy9OazBjSEMvaURhd21wWkF0NG1CdEFvVFNUYmpORnZuSkdjRlJh\n" +
					"ZVJWCmFxQ0NjaWFGeHJoWXJrZmlFSWNWMWhkQ2NFdFJRNFplM21XUTErTzk4dG1V\n" +
					"Vyt2SUQ2MTg4NC9wYk9rcWJGZEUKWlRob2t4RVV4KzJIMDdYMXFBT2ViaWo0UjV4\n" +
					"NDZFUmJEZmRaSWl4VzVadWoxNEYvOUVOYkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQ\n" +
					"VUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElD\n" +
					"IEtFWS0tLS0tCk1JR0pBb0dCQVBMTzNQZzNuSDBibHVEaVQ0dGhJNjVRNEpXMlln\n" +
					"M2w1b3ptNENBcWNWVXZNams4c0M4K1lHMnYKbXc3TnRmb2hCTU1NOXoxTWxyKzdE\n" +
					"WWwxQ2d6SWhCOGJETlhWQWZ4dW1YdnR4S0dFakxrS29EblZibGlpU3F5NgpBUzZ3\n" +
					"Wm0zN09KNUt4VVZ6SW9EWUwvNGhsR0F1aVpLVUIzbDJiOXhabXNteVlJVEowL3ls\n" +
					"QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rp\n" +
					"b24tcG9pbnQgaHYzZnl3ZG16a2Z1ZzYzd3M3dmN6enZmY21qZmdjdnIKaXAtYWRk\n" +
					"cmVzcyAxOC40OS41LjM3Cm9uaW9uLXBvcnQgOTA1Mgpvbmlvbi1rZXkKLS0tLS1C\n" +
					"RUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUsrb29Udm4zc0dib3Fn\n" +
					"dGRaWTFPUm4vSk1wOVhwUlZ6Qm01WmE4UWY4WG1xUEl4TWhFWGlXRkkKRXFDRDhm\n" +
					"VW0ya1dEUTZNTVJoWWQ4cDlFeG9rV3QvTEJUejAxUTRpOGRacnhQNGVhbG92Q2NY\n" +
					"c3pJTzFsQ3hFeAorN0hGV2NwTCtLcWk0R2U1aFk3RUE5azFaNENqZlIrUzljcFl1\n" +
					"SytaYXkrTmVCQ2ZDZm5KQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVkt\n" +
					"LS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"TUlHSkFvR0JBTFNSaXZ5UUZhN3FabjdVeWV4Sm5MSVI4MUVhRlhiZ0dPcGExbFNj\n" +
					"RTc3cnZZM3k5eXNqNlRYWQpSUExNRnJqaFRmOFlxSDBRRjE4aWNkSFNSOTgra2ZX\n" +
					"dTEzZ2pXQVZURkxZOG1ueDdGZXpwRDRYUmh2cWNId3RDClp4SzFyNGVYV3B0M2Nh\n" +
					"QkRVSVl0ckdULzk5d3YxN2dERkhJeHJQQ2NNeWhHbk04bDJmenhBZ01CQUFFPQot\n" +
					"LS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2ludCBq\n" +
					"a2o2anpyNXBicWMyZ3lvcXU3aGFqYW1tc3pmbmV3ZQppcC1hZGRyZXNzIDE5NC41\n" +
					"OS4yMDcuMTk1Cm9uaW9uLXBvcnQgNDQzCm9uaW9uLWtleQotLS0tLUJFR0lOIFJT\n" +
					"QSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTFFMRTJMRjluU0tacFZxOHVkbmc1\n" +
					"MTU3a2tja21RS0M2OTlKK1VxTmFTRVY2eXo3NktaUldrdwpKM2dOMHE2bUNHVXM3\n" +
					"YnROZ0F4NXZsaVowTmJJQVlmTnFmQTljRjVsTEVyTHp1M25YcXhmanpreDM0VDd6\n" +
					"VkNhCnNSeE93OHliYVRTUWwrbTNjOWR2MGdSNXNCOVNueUprWlg3bWRHNzV5NWFJ\n" +
					"Z2ZHMGdDb0JBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNl\n" +
					"cnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9H\n" +
					"QkFMVXFMWVBKZnF4MGNlWElHTnlFdEZwRUxDdE5ob0VzNlhGS1hWUWMzYi96dzBE\n" +
					"SGhZZmMzRFZPCmNiYjExd0ljYVJaQm5sNmlNT2dLWWpGSUpmVkt3M1YraW1rVmRM\n" +
					"MzRZQmFGd292NlZZbmxmSkpaNmNXbDFnbkIKN3B4ZkpHdTRXNkorczZVWjVYUHR1\n" +
					"dTdLU3hjV0kxcVFYSmtTVWNMOGE2TnE0UzJvRlpqZEFnTUJBQUU9Ci0tLS0tRU5E\n" +
					"IFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"-----END MESSAGE-----\n",
				"hsdir2-fingerprint": "-----BEGIN MESSAGE-----\n" +
					"aW50cm9kdWN0aW9uLXBvaW50IHl1bHFkZWluNWtteTZ0MnJmYjVoZG43amlyZTJo\n" +
					"Mm40CmlwLWFkZHJlc3MgMjEzLjE1My44NS44Mgpvbmlvbi1wb3J0IDk5Mwpvbmlv\n" +
					"bi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU9N\n" +
					"dkkvQkVVc1pVSWluYS9ZRldnbGlIV0EzRkN5ZTMrSWFJK2ltZmtDbjBzYlVjMms0\n" +
					"Mmx0MmcKK0FNZ0dxaDZ2SFUwV204YTJuNGRDdTBEV3FRZzRHV05Zd1FjcVhFSG1u\n" +
					"WGVTTTZTK0hiQ29HL3U1ZVQ5cThhQgowbjhOYkV1dkVhcEhiVmRkZDlGWHdLMVd5\n" +
					"MStSdnFRTERDTTJwSFRWUXZuNklLV0F5c1gxQWdNQkFBRT0KLS0tLS1FTkQgUlNB\n" +
					"IFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJM\n" +
					"SUMgS0VZLS0tLS0KTUlHSkFvR0JBSjc1S3JzTXZ1UnIybzdCZGd1R1UzbTlmRGlj\n" +
					"OFIxVnYrUGF5NjYyS01sNHNBTG9GUGJLTHdYZQpocWtjNzJlblFZV25WbnJtNzls\n" +
					"ZTZJS0k2SmNNVll3bVR6dll0dHJ5VjlXMmRVcDVrU2ZaRXRGZU54VlFvbjdWClNx\n" +
					"MldPYkFKM1dpeDlpQ1VMSHR5M2l6TjlmVlFjbHUxeWhHZGpXMUJEenlPRTMyUGR4\n" +
					"TzVBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVj\n" +
					"dGlvbi1wb2ludCAzZnkyanltYmN5djV0aDdvanF2bm1ib3dhc3NwMnhrbAppcC1h\n" +
					"ZGRyZXNzIDE5My4xMS4xMTQuNjkKb25pb24tcG9ydCA5MDAyCm9uaW9uLWtleQot\n" +
					"LS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTmxRWUVJeGU2\n" +
					"eDRKQ3N0YUFjTXNtZzJnd0RmTkp4cE5UbHFCejhHbTQvWjJLb3hNUFVnenpvWQow\n" +
					"elZqL014ZWJpczF0R0JOdWdLMVpYM2pKcnpOU005RXQ3bjd3T1VicnhwNlBzYW9G\n" +
					"TG82eE5CVUlJVStSRDkzCmZMd1lkZVB3L2ZWWTYzRE5leWV5SUJLSEVNRXBickpJ\n" +
					"ZVRZdTVadXlvekRJenlzaXZ3MnRBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElD\n" +
					"IEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVkt\n" +
					"LS0tLQpNSUdKQW9HQkFLdlVaTE5OV1Njb2VHSExTZlUvYThJSVhFVUdGRWtFQUpW\n" +
					"V3NkbnV0TWN3N3pHcjFjQ04zUlZwCitEcm9qUlVUV2o3NGdaZ3dVbUpSSzNEemtW\n" +
					"dWNNRm9aRGRRK29odi8zRll3cEY0anFPQWFJa2IvOGswYnprT0kKUVR2bnBHdWo2\n" +
					"TUU0aFRUNzJuelZxVDVNNHRGUllxaVc5aGFnd3J1NHRYUGJzNzdWdnFUckFnTUJB\n" +
					"QUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBv\n" +
					"aW50IDJtamxjbmh4eWp3ZDN6c2szNXc3eXlpam1mdm9zajZxCmlwLWFkZHJlc3Mg\n" +
					"MzcuMTIwLjE2Ny4xNzUKb25pb24tcG9ydCA5OTMKb25pb24ta2V5Ci0tLS0tQkVH\n" +
					"SU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNRVBNc2xOaWtBYXY4a0Z2\n" +
					"SG5CV3VwQ2hmOXYwazhWNEZ4QTQ2SU14dGdZTHlSSitUQ2w4My96Cncwdllkalpp\n" +
					"OTEzRDdmekdMbGc0OGIzVWgwRlVjOEcvc3owcEJrVzgwemtzV2R0QmRweUI2K25J\n" +
					"SFV2TzNScDEKUEhtaVNnMGpIblJtalBFMVY0Z2lTMG1kSUhmRlJOaEpicEg2UHls\n" +
					"amlMTTl4SjNtZHdQUkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1J\n" +
					"R0pBb0dCQU9lRUNLVUhDL0JJbnZrWXBTQzJSSlk4Sk9XdU93WmVqYythSHhRVnBR\n" +
					"MTBhVmVuajFZN3JNd2YKZUdEaDIyNEM2TS82NWZlVWw1VHJuMVlLdmFseGtDemhE\n" +
					"U1BySE1XVmFDandnQ0E1RWdsRFJ5ZmJpYy9wUW9RUQpmTnlxekY5UGdBVWhkZ1Ax\n" +
					"eGloaTRZWGQyUGVSN2xlNzhFSHMrbGgzZFZ5b2tEZXg0RmdSQWdNQkFBRT0KLS0t\n" +
					"LS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQgdnN4\n" +
					"Y3U0YWF3azdsYmJ5ZXZrcWtmeG9rM3Z1b2xjdGQKaXAtYWRkcmVzcyAxOTUuMTU0\n" +
					"LjI0MS4xMjUKb25pb24tcG9ydCA0NDMKb25pb24ta2V5Ci0tLS0tQkVHSU4gUlNB\n" +
					"IFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFOaXkwUUFzQzkva2hkeFpXRUM4b1JV\n" +
					"UFJKQ2JOY2lWQ1VkNjF3NDFFY3NlVHJzVXZoNnNBcmtaCm4rVS9pdVBXWmw0ZytJ\n" +
					"QjVrTWFieG5VMENRZ2lncGVGLzkwMUxGMldMYzEvT0ZIeGsvUCtTaVdnZWc3T2hT\n" +
					"Z0MKQ0k1WGhpbmpsQTJLdWxiSVRrS2RFeXY4ek9QVDgrMm1UUDA2Zi9OOURhYW15\n" +
					"OGt5REMrbkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2Vy\n" +
					"dmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dC\n" +
					"QUw4UkZaZnN6eS9Od0ZsaDNXMm1ZMHRVcGtpKzYrVWpNM0FOc0JmNUFjOEh4d0Zl\n" +
					"YU9KNy9FaXoKZTE1ZlU0ZkVpd0EzVE0rWkFmYXBOc1dzOGV1NmlFVUZlVVZqSWhB\n" +
					"YXRRUlJrYTdGcjVJMStqRDA3bGJ0WVFQYQo4YTk4eG9HZks3bWZXYm1qNXpheHB1\n" +
					"TE1sYkhybkh3N1FwcmREUi9EYjcrbnc4aDFFK3J0QWdNQkFBRT0KLS0tLS1FTkQg\n" +
					"UlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQgcDM3d2duaWZ3\n" +
					"Z2FnM3VrdnF5amlqZXB0NHR3cDM2cmoKaXAtYWRkcmVzcyAxMzYuMjQzLjEzMS4y\n" +
					"OQpvbmlvbi1wb3J0IDkwMDEKb25pb24ta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJ\n" +
					"QyBLRVktLS0tLQpNSUdKQW9HQkFMeGRxL21nSGFBWXlPTnNvS1ExZTdmaW5ZQTVw\n" +
					"QWlEaUI4Q0dSdEY2T29aS0FsRENaVzNxd0FyCkkwNzZCUmc2ZVRYZmF4anl3WW83\n" +
					"eGFiWnVValcwcExRNE1vLzZkQXB1NkxpVHA3L25LNjdxUlhDdUNSUWY3RkwKTGhY\n" +
					"YjVZM3doL05TZHBNQi9yRGx5UXNCOGdmWEtHWS8xMWp2OFd5RkhvZTN5NEFxUDZU\n" +
					"RkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2VydmljZS1r\n" +
					"ZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUpnekJ6\n" +
					"WTE3c29xNUR6cHcwQmx3c3RQVlhvUjNiOHQySGU1VjRZK29jSVhmZFR0Q3YvZ2ow\n" +
					"S3MKVGdWdzZCN3VuSU9XTVZ0dERyb1RicHNmQkhtcHpZMnQrakRkUnhtc2tObUwz\n" +
					"Um9kSG5VSWlyeEZ1d2tJdkhPbwp4cDArSElqc0lqUy80MVFsWGZDdGQwNDdFaEd2\n" +
					"MStINXBNVS9HWFZYajdDck5nQnZSaUREQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBV\n" +
					"QkxJQyBLRVktLS0tLQoKaW50cm9kdWN0aW9uLXBvaW50IHdpY240NW50b2JzbzYy\n" +
					"c21ub3h6a3hjeGVybHkyY3pzCmlwLWFkZHJlc3MgMTkyLjQyLjExNS4xMDEKb25p\n" +
					"b24tcG9ydCA5MDAzCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZ\n" +
					"LS0tLS0KTUlHSkFvR0JBTDNsTzBqTmQ5YVNVL3doWmZQWk80YjFoZXd2eW8wV0Vz\n" +
					"V3F2UlNKQXBLRzBXZ2gxdzdCNjl3eQpyUE45Yytsb2tkVlZocE9JeXE1aEtudGF0\n" +
					"cnVzSVVMTGRoKzQ0ZUFJOXJROUxQVGFmUHl0ZVpBMTRMMXlsVndnClRUUHZuRFlK\n" +
					"T0hvdmNyVzQ1UW81emhQUGo4bFFvenZramxtRGo0V2JQZHhXc1lmN1BiYlZBZ01C\n" +
					"QUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0t\n" +
					"LS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFOb0JuQjU2d0J6\n" +
					"eGREZzZmZ21QWTJmaWlWWHJIQU9oc0ZhR240VEpBWm1DUm1aUFpEaVpIZTdnCnRB\n" +
					"QTRlcEN6VkRhOXNhODM0RTVSNEp1ekMwUXRLdzJERU5QRUdhTEN6WUxXd3dvZ0JL\n" +
					"dkZOTnAvL1N4SS85OXIKeFZmaEs5MmxHVHlTVklUVytVM2M0dWRkN0FvYXhMSFM1\n" +
					"ZEFXQktUUjJlNkFWWTcvSWp1akFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMg\n" +
					"S0VZLS0tLS0KCmludHJvZHVjdGlvbi1wb2ludCByMjNzZjZxMjVobzZkZWtseWlw\n" +
					"NnVpdWJ0dmc2dGhudQppcC1hZGRyZXNzIDE5NS4xODkuOTYuMTQ4Cm9uaW9uLXBv\n" +
					"cnQgNDQzCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"TUlHSkFvR0JBTUJPeEkrWnFNQVU5ZHBjS2lMcjVJWjBnOUU4T2hVL2hBbzJWc3Zw\n" +
					"SjhSaW9iTURRSkR5djVKYwpRRW02eTltQ0NpQlhjNlBURnh4QTJ3dG9YUVl4UUNK\n" +
					"RFk3cDJLekh3ZisyWmY2ekE5TGFiVFdnYjY1Z2Q1MVZrCnpaWmFiOWkxcGNkQWhn\n" +
					"WUdRNTNzbzNubytielgxNkVqT1BCYlMxSDdIc24yY3JLT1EzUDNBZ01CQUFFPQot\n" +
					"LS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVH\n" +
					"SU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFOTVNnYXlQQlBOY3pmbnlo\n" +
					"ZG11L2ZNUW92ZW85UWRpNlo1dHpxbzlrTXdZZ2JTcXVDcWtad2s4CjhiNnhYRTlM\n" +
					"NDFsd2trTFlkYUlYdkhIRnNIbGlhRzhlNzFaOERpQ05xVGlpaEZRWXY3N29hUzAy\n" +
					"dDZPdjMzdE8KTUFNbmRCOTBubTdCbHpoRStIMDhlNTRST3hiQWhoQU1KVUEzWGxC\n" +
					"UThwRkEvbUE4MzVJdkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0KaW50cm9kdWN0aW9uLXBvaW50IDNnaWtydHo1ejdsbnRocXR3aXluZG40aWlo\n" +
					"a2ZuZHNrCmlwLWFkZHJlc3MgMTQxLjcwLjEyNS4xNQpvbmlvbi1wb3J0IDkwMDEK\n" +
					"b25pb24ta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9H\n" +
					"QkFLY05WeXAwN2RwSFBQRWpHdnhkbzdxY0tWMWpMbzVQa09LZ0xZVFJCa2dhcVds\n" +
					"S1k4ZmMyRUxyClFtaTRVYmlDQkdncWpxbkVmQ1Z1UXB1bUk4K2ZGU1Y0UFlLcnly\n" +
					"elRzcjUrL1dYbWVGNU81bU1qYUhWcXVVNXEKaWlzWmxmdU9wdjZ5NUd3eUFGMFRw\n" +
					"TXJRSE5tc3Exd1FuR2JnT0xRRWtzdEkveExXQlJ1UEFnTUJBQUU9Ci0tLS0tRU5E\n" +
					"IFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0Eg\n" +
					"UFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1jVHpVOUQ2ZE5pak9xTGFMdmYxVDdX\n" +
					"VDVSeGpmUTdGaWZSaFF6YVVrOUVOWTk5a3ZQZitvencKT3JJbk9taUZ5V2FPcmtN\n" +
					"QkgxODV1SGRNVW1OeUtETEpTekhNTFNiOFJhYkpmbmpnd2VKT2RmeVEycFA0cFlv\n" +
					"RwpkYmdqMzdVejFIOFM5MGp0Tno0RjVDdW45V1BLdHg1ejJEcllwQkpTYk9EZnlW\n" +
					"Sjg2V1hWQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRy\n" +
					"b2R1Y3Rpb24tcG9pbnQgem81ZWI1Nno2a2NwaTZyZWgzcm1iYXBqbTJiaGloamMK\n" +
					"aXAtYWRkcmVzcyAxNzYuOS4zOS4xOTYKb25pb24tcG9ydCA5MDAxCm9uaW9uLWtl\n" +
					"eQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTVRCb0hu\n" +
					"YXFjS1JKbHkxYlVWS0VWUTJPSGdjdGdWcUloOWFvQ1VSNHJHdmV6cGdLVXhSM3ky\n" +
					"QQowbm5zYlFUWXBSbXVxK0lNOE5nYm1GdFR1V2MxWWo3VHJXZ1RGMzV1LzZKbmxu\n" +
					"NWYyeTBqb1EzSStBbmxZVFQwCjFiM25xMFVFemZkZ00yVGZkNmNtZUdKN1B0SG9P\n" +
					"T2l2VEZnVHVZTDdRVENmU3E5L0VwMC9BZ01CQUFFPQotLS0tLUVORCBSU0EgUFVC\n" +
					"TElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBL\n" +
					"RVktLS0tLQpNSUdKQW9HQkFKNXViaFEwU2xpSWc5K2I5czdUN294RFJROGlySGlS\n" +
					"Ykh5TXFRbGdPL1dwdFVHMGloRVFmZUoxCmk2L0QyY1N6OXZYaVoxaEZBdUtJRU1a\n" +
					"SkJkR3VuamphZ0pucHpaSVl4ZHJXUFpKTzdDYlAxQlcwUWJ5WSsxb1gKMUt5Zzcw\n" +
					"d3JseUVUekIyOERPbS91ME9oL2l1NDk5MWZ4ZXI4V1pCU0dPQzZaNGs3SWtBakFn\n" +
					"TUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9u\n" +
					"LXBvaW50IHhvYnQzMjRpZmw0a3phZ2N5ejYzZmxjcG9ham13ZWxyCmlwLWFkZHJl\n" +
					"c3MgMzcuMTg3Ljk2Ljc4Cm9uaW9uLXBvcnQgOTAwMQpvbmlvbi1rZXkKLS0tLS1C\n" +
					"RUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1WSlk4RzJTNVladEdX\n" +
					"L1RUMHZNWFdXanpndWF2bzkzaWZJZU1HNVBnQWNwRnV6dUpSZEJPTGkKZ0xicmxT\n" +
					"elFDbytJWGhDamU5bDV3czhlekYvaFRKbTdHNVJndEcwS245blJxMEYvS1lNaGo2\n" +
					"RDI2bGFhdUYyTQowSEk2bGlQZ3R6OUdhRnptc1Q4UkV0WmZHMGRPK2tZaHlNeFpP\n" +
					"Y3lXcS9jN2I5cnFlM28zQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVkt\n" +
					"LS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"TUlHSkFvR0JBTkYzTitEZ3czT2x3MW1ITzlKT2QyWWpzMDlPZUpWTUI5bEJDNzVD\n" +
					"R093c0E5S29qMHIxVGZRNAp6a3Vqc1hieTlvb2RBZXpsM0w5QWl6RmV5L2RKck4v\n" +
					"N0ZpdCt4V1h1TWlJTThuSXpDZ2xGN2d1bzJJb21wSmJwCkNPV0VjVTRjbUxKTUZZ\n" +
					"NUtzb1E1TzQ2QTBzS1Q2YlppOEY3WHJ4bHdSVFRwVk5yTTA0aWpBZ01CQUFFPQot\n" +
					"LS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCg==\n" +
					"-----END MESSAGE-----\n",
				"hsdir3-fingerprint": "-----BEGIN MESSAGE-----\n" +
					"aW50cm9kdWN0aW9uLXBvaW50IHlxa3BmZDZzeDNhdmttYmVmZ250ZHZoaGUyN2xy\n" +
					"ejRpCmlwLWFkZHJlc3MgMTg4LjEzOC4xMTIuNjAKb25pb24tcG9ydCAxNTIxCm9u\n" +
					"aW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JB\n" +
					"UEVVN1lCWTJqUVFEbmx1SVowRlhJUHZ3eHgreUpLK1NtN1g1ekNPb0NTQkpRSXRU\n" +
					"WTVQeWtZZgptOGQyNzlpQ2NPNk9FZFJFOW54SE5LUUFiOFVQWjRWSWt4SU1QS0gy\n" +
					"S25SVHhQL0JseGR0ditidStzSEhLRVJxCjJVZWRVTk9VOW1xQzk5M216WEI3ejhP\n" +
					"eXp1QVBsNTV5Y3hBdmFaNWZ3TlV3Sy92RnlZcnRBZ01CQUFFPQotLS0tLUVORCBS\n" +
					"U0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBV\n" +
					"QkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMUVlXcUtJZkZ0V09LSmZreFc3L1NxM2ZM\n" +
					"aWlsM1RoUkpxa241cFQvTjA2ckNQQTV5VDk0WE44ClNDblNJQ3Jhb2t4cXI2OXJx\n" +
					"bzloRDlxYTVnczhoUnFoQlROdFJiN3RScWdKZ09YaURSQUZ6eFlad3ZhWk9taWcK\n" +
					"TWZHUGs4Tk11UldXYnluV2ZHcVZVam9MNHcvQStpaUdDRVhGTklYY3JyMTdFMytR\n" +
					"ZHhzVkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9k\n" +
					"dWN0aW9uLXBvaW50IDM1NWtjM3EybWEzNGw3ZjNqeHd1Nm90bTJqcm11bjR6Cmlw\n" +
					"LWFkZHJlc3MgMTk1LjE1NC4yNTMuMjI2Cm9uaW9uLXBvcnQgNDQzCm9uaW9uLWtl\n" +
					"eQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTUI3WFUv\n" +
					"MkJJaGJDSktNb1NtUnlhNjZnRXNpcHFDakxHUUcxT2xTb1lveFUwNTBYRTZ5VnBh\n" +
					"YgpvT1d4eVYwT2xLNXNJSjNaM2FXM3Qra1FUOGZqNHFwQjV6ZWg2V0dSVmN0bStH\n" +
					"NkVScEZkVFFHMkdTMjg5VVE1Ci93aDk2Nm5xSVhzSnJWNzBKa1BMOUVsMllRZm9N\n" +
					"MG5oSHlJclBhN1lRNVNqSEtIUTZTRnRBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVC\n" +
					"TElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBL\n" +
					"RVktLS0tLQpNSUdKQW9HQkFLUmVxQjhKYmhpRjZycW9NVk1xODlEeHlRN1dBMDI1\n" +
					"aTF5VEFHQkM5bFR2RjZYWldLQmpzU0ZpCmo1SDUwKzBLS284eU1GNWRUYUd2d01X\n" +
					"VllMNzRFNVlQOTU3Qi81bXJPOFowc3RERHNEK3FMdmdCRjdUWmpxOGEKOFFjQXVm\n" +
					"V3d1Y3hqUU5wK1lRdzFuamtIOEpEdjBsb3lFY0dHQVk3T3pUUUkvM3ZGaklaTEFn\n" +
					"TUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9u\n" +
					"LXBvaW50IGl5b3c1aWt6bTNkN3RnMmQybjVueWVsbGxvaGVwdWpxCmlwLWFkZHJl\n" +
					"c3MgNTEuMjU0LjQ1LjQzCm9uaW9uLXBvcnQgOTAwMQpvbmlvbi1rZXkKLS0tLS1C\n" +
					"RUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUs2NExRRWhrRkhybitE\n" +
					"RHhUS01kNGxZR1FHMjVPWHpQNk5ldEJzVk1mNHQ1Q0lqT1VaWXU1SDcKU21oYVJB\n" +
					"RitMOE5PbTlJVmRSZVhpK2srL0thdnRwb2xJVU04VEhQMm9ZMk5yOUlHanEvT0pZ\n" +
					"OUtwSllQMTlKbgpndDI2cHEzSFpzWDA2ZWE2emdmTTc5VllucmZ5QjNPN2VJUUNt\n" +
					"TkhIWGZoSGhNQmtVb0JmQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVkt\n" +
					"LS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"TUlHSkFvR0JBTU5FM1JZZUFhNmpQYjlsWldDZUVDM2liSWVNR3k5MFZwcE13aHBV\n" +
					"U1FpVmMwazFENU8xWjZ4Kwp0TzFSVC8wZ3ZZdWdmdGcyNUl0OE0yamVQRWNRVk91\n" +
					"NlJGazZzeGpjeVhERnA1aytVdVRFSnhRcU45akhyZ0ZwCkoxZy9IUkxPZHV1UEow\n" +
					"TXczWGE1OFVOc25mdEdueGhXRlVnQWlEN3UrcUxtY1BTMjBrSUJBZ01CQUFFPQot\n" +
					"LS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2ludCBk\n" +
					"b3AyejRzNmM3amc0bWQ2dTdoMnB2Y3Z3ZmNsYW14ZgppcC1hZGRyZXNzIDgyLjk0\n" +
					"LjI1MS4yMjcKb25pb24tcG9ydCA0NDMKb25pb24ta2V5Ci0tLS0tQkVHSU4gUlNB\n" +
					"IFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMR0ptMG5SSWZzQ1N5Qy9OazBjSEMv\n" +
					"aURhd21wWkF0NG1CdEFvVFNUYmpORnZuSkdjRlJhZVJWCmFxQ0NjaWFGeHJoWXJr\n" +
					"ZmlFSWNWMWhkQ2NFdFJRNFplM21XUTErTzk4dG1VVyt2SUQ2MTg4NC9wYk9rcWJG\n" +
					"ZEUKWlRob2t4RVV4KzJIMDdYMXFBT2ViaWo0UjV4NDZFUmJEZmRaSWl4VzVadWox\n" +
					"NEYvOUVOYkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2Vy\n" +
					"dmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dC\n" +
					"QVBMTzNQZzNuSDBibHVEaVQ0dGhJNjVRNEpXMllnM2w1b3ptNENBcWNWVXZNams4\n" +
					"c0M4K1lHMnYKbXc3TnRmb2hCTU1NOXoxTWxyKzdEWWwxQ2d6SWhCOGJETlhWQWZ4\n" +
					"dW1YdnR4S0dFakxrS29EblZibGlpU3F5NgpBUzZ3Wm0zN09KNUt4VVZ6SW9EWUwv\n" +
					"NGhsR0F1aVpLVUIzbDJiOXhabXNteVlJVEowL3lsQWdNQkFBRT0KLS0tLS1FTkQg\n" +
					"UlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQgaHYzZnl3ZG16\n" +
					"a2Z1ZzYzd3M3dmN6enZmY21qZmdjdnIKaXAtYWRkcmVzcyAxOC40OS41LjM3Cm9u\n" +
					"aW9uLXBvcnQgOTA1Mgpvbmlvbi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtF\n" +
					"WS0tLS0tCk1JR0pBb0dCQUsrb29Udm4zc0dib3FndGRaWTFPUm4vSk1wOVhwUlZ6\n" +
					"Qm01WmE4UWY4WG1xUEl4TWhFWGlXRkkKRXFDRDhmVW0ya1dEUTZNTVJoWWQ4cDlF\n" +
					"eG9rV3QvTEJUejAxUTRpOGRacnhQNGVhbG92Q2NYc3pJTzFsQ3hFeAorN0hGV2Nw\n" +
					"TCtLcWk0R2U1aFk3RUE5azFaNENqZlIrUzljcFl1SytaYXkrTmVCQ2ZDZm5KQWdN\n" +
					"QkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQot\n" +
					"LS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTFNSaXZ5UUZh\n" +
					"N3FabjdVeWV4Sm5MSVI4MUVhRlhiZ0dPcGExbFNjRTc3cnZZM3k5eXNqNlRYWQpS\n" +
					"UExNRnJqaFRmOFlxSDBRRjE4aWNkSFNSOTgra2ZXdTEzZ2pXQVZURkxZOG1ueDdG\n" +
					"ZXpwRDRYUmh2cWNId3RDClp4SzFyNGVYV3B0M2NhQkRVSVl0ckdULzk5d3YxN2dE\n" +
					"RkhJeHJQQ2NNeWhHbk04bDJmenhBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElD\n" +
					"IEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2ludCBqa2o2anpyNXBicWMyZ3lvcXU3\n" +
					"aGFqYW1tc3pmbmV3ZQppcC1hZGRyZXNzIDE5NC41OS4yMDcuMTk1Cm9uaW9uLXBv\n" +
					"cnQgNDQzCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"TUlHSkFvR0JBTFFMRTJMRjluU0tacFZxOHVkbmc1MTU3a2tja21RS0M2OTlKK1Vx\n" +
					"TmFTRVY2eXo3NktaUldrdwpKM2dOMHE2bUNHVXM3YnROZ0F4NXZsaVowTmJJQVlm\n" +
					"TnFmQTljRjVsTEVyTHp1M25YcXhmanpreDM0VDd6VkNhCnNSeE93OHliYVRTUWwr\n" +
					"bTNjOWR2MGdSNXNCOVNueUprWlg3bWRHNzV5NWFJZ2ZHMGdDb0JBZ01CQUFFPQot\n" +
					"LS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVH\n" +
					"SU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMVXFMWVBKZnF4MGNlWElH\n" +
					"TnlFdEZwRUxDdE5ob0VzNlhGS1hWUWMzYi96dzBESGhZZmMzRFZPCmNiYjExd0lj\n" +
					"YVJaQm5sNmlNT2dLWWpGSUpmVkt3M1YraW1rVmRMMzRZQmFGd292NlZZbmxmSkpa\n" +
					"NmNXbDFnbkIKN3B4ZkpHdTRXNkorczZVWjVYUHR1dTdLU3hjV0kxcVFYSmtTVWNM\n" +
					"OGE2TnE0UzJvRlpqZEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0KaW50cm9kdWN0aW9uLXBvaW50IHl1bHFkZWluNWtteTZ0MnJmYjVoZG43amly\n" +
					"ZTJoMm40CmlwLWFkZHJlc3MgMjEzLjE1My44NS44Mgpvbmlvbi1wb3J0IDk5Mwpv\n" +
					"bmlvbi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dC\n" +
					"QU9NdkkvQkVVc1pVSWluYS9ZRldnbGlIV0EzRkN5ZTMrSWFJK2ltZmtDbjBzYlVj\n" +
					"Mms0Mmx0MmcKK0FNZ0dxaDZ2SFUwV204YTJuNGRDdTBEV3FRZzRHV05Zd1FjcVhF\n" +
					"SG1uWGVTTTZTK0hiQ29HL3U1ZVQ5cThhQgowbjhOYkV1dkVhcEhiVmRkZDlGWHdL\n" +
					"MVd5MStSdnFRTERDTTJwSFRWUXZuNklLV0F5c1gxQWdNQkFBRT0KLS0tLS1FTkQg\n" +
					"UlNBIFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQ\n" +
					"VUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBSjc1S3JzTXZ1UnIybzdCZGd1R1UzbTlm\n" +
					"RGljOFIxVnYrUGF5NjYyS01sNHNBTG9GUGJLTHdYZQpocWtjNzJlblFZV25WbnJt\n" +
					"NzlsZTZJS0k2SmNNVll3bVR6dll0dHJ5VjlXMmRVcDVrU2ZaRXRGZU54VlFvbjdW\n" +
					"ClNxMldPYkFKM1dpeDlpQ1VMSHR5M2l6TjlmVlFjbHUxeWhHZGpXMUJEenlPRTMy\n" +
					"UGR4TzVBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJv\n" +
					"ZHVjdGlvbi1wb2ludCAzZnkyanltYmN5djV0aDdvanF2bm1ib3dhc3NwMnhrbApp\n" +
					"cC1hZGRyZXNzIDE5My4xMS4xMTQuNjkKb25pb24tcG9ydCA5MDAyCm9uaW9uLWtl\n" +
					"eQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTmxRWUVJ\n" +
					"eGU2eDRKQ3N0YUFjTXNtZzJnd0RmTkp4cE5UbHFCejhHbTQvWjJLb3hNUFVnenpv\n" +
					"WQowelZqL014ZWJpczF0R0JOdWdLMVpYM2pKcnpOU005RXQ3bjd3T1VicnhwNlBz\n" +
					"YW9GTG82eE5CVUlJVStSRDkzCmZMd1lkZVB3L2ZWWTYzRE5leWV5SUJLSEVNRXBi\n" +
					"ckpJZVRZdTVadXlvekRJenlzaXZ3MnRBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVC\n" +
					"TElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBL\n" +
					"RVktLS0tLQpNSUdKQW9HQkFLdlVaTE5OV1Njb2VHSExTZlUvYThJSVhFVUdGRWtF\n" +
					"QUpWV3NkbnV0TWN3N3pHcjFjQ04zUlZwCitEcm9qUlVUV2o3NGdaZ3dVbUpSSzNE\n" +
					"emtWdWNNRm9aRGRRK29odi8zRll3cEY0anFPQWFJa2IvOGswYnprT0kKUVR2bnBH\n" +
					"dWo2TUU0aFRUNzJuelZxVDVNNHRGUllxaVc5aGFnd3J1NHRYUGJzNzdWdnFUckFn\n" +
					"TUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9u\n" +
					"LXBvaW50IDJtamxjbmh4eWp3ZDN6c2szNXc3eXlpam1mdm9zajZxCmlwLWFkZHJl\n" +
					"c3MgMzcuMTIwLjE2Ny4xNzUKb25pb24tcG9ydCA5OTMKb25pb24ta2V5Ci0tLS0t\n" +
					"QkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNRVBNc2xOaWtBYXY4\n" +
					"a0Z2SG5CV3VwQ2hmOXYwazhWNEZ4QTQ2SU14dGdZTHlSSitUQ2w4My96Cncwdllk\n" +
					"alppOTEzRDdmekdMbGc0OGIzVWgwRlVjOEcvc3owcEJrVzgwemtzV2R0QmRweUI2\n" +
					"K25JSFV2TzNScDEKUEhtaVNnMGpIblJtalBFMVY0Z2lTMG1kSUhmRlJOaEpicEg2\n" +
					"UHlsamlMTTl4SjNtZHdQUkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZ\n" +
					"LS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0t\n" +
					"Ck1JR0pBb0dCQU9lRUNLVUhDL0JJbnZrWXBTQzJSSlk4Sk9XdU93WmVqYythSHhR\n" +
					"VnBRMTBhVmVuajFZN3JNd2YKZUdEaDIyNEM2TS82NWZlVWw1VHJuMVlLdmFseGtD\n" +
					"emhEU1BySE1XVmFDandnQ0E1RWdsRFJ5ZmJpYy9wUW9RUQpmTnlxekY5UGdBVWhk\n" +
					"Z1AxeGloaTRZWGQyUGVSN2xlNzhFSHMrbGgzZFZ5b2tEZXg0RmdSQWdNQkFBRT0K\n" +
					"LS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQg\n" +
					"dnN4Y3U0YWF3azdsYmJ5ZXZrcWtmeG9rM3Z1b2xjdGQKaXAtYWRkcmVzcyAxOTUu\n" +
					"MTU0LjI0MS4xMjUKb25pb24tcG9ydCA0NDMKb25pb24ta2V5Ci0tLS0tQkVHSU4g\n" +
					"UlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFOaXkwUUFzQzkva2hkeFpXRUM4\n" +
					"b1JVUFJKQ2JOY2lWQ1VkNjF3NDFFY3NlVHJzVXZoNnNBcmtaCm4rVS9pdVBXWmw0\n" +
					"ZytJQjVrTWFieG5VMENRZ2lncGVGLzkwMUxGMldMYzEvT0ZIeGsvUCtTaVdnZWc3\n" +
					"T2hTZ0MKQ0k1WGhpbmpsQTJLdWxiSVRrS2RFeXY4ek9QVDgrMm1UUDA2Zi9OOURh\n" +
					"YW15OGt5REMrbkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"c2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pB\n" +
					"b0dCQUw4UkZaZnN6eS9Od0ZsaDNXMm1ZMHRVcGtpKzYrVWpNM0FOc0JmNUFjOEh4\n" +
					"d0ZlYU9KNy9FaXoKZTE1ZlU0ZkVpd0EzVE0rWkFmYXBOc1dzOGV1NmlFVUZlVVZq\n" +
					"SWhBYXRRUlJrYTdGcjVJMStqRDA3bGJ0WVFQYQo4YTk4eG9HZks3bWZXYm1qNXph\n" +
					"eHB1TE1sYkhybkh3N1FwcmREUi9EYjcrbnc4aDFFK3J0QWdNQkFBRT0KLS0tLS1F\n" +
					"TkQgUlNBIFBVQkxJQyBLRVktLS0tLQo=\n" +
					"-----END MESSAGE-----\n",
				"hsdir4-fingerprint": "-----BEGIN MESSAGE-----\n" +
					"aW50cm9kdWN0aW9uLXBvaW50IHAzN3dnbmlmd2dhZzN1a3ZxeWppamVwdDR0d3Az\n" +
					"NnJqCmlwLWFkZHJlc3MgMTM2LjI0My4xMzEuMjkKb25pb24tcG9ydCA5MDAxCm9u\n" +
					"aW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JB\n" +
					"THhkcS9tZ0hhQVl5T05zb0tRMWU3ZmluWUE1cEFpRGlCOENHUnRGNk9vWktBbERD\n" +
					"WlczcXdBcgpJMDc2QlJnNmVUWGZheGp5d1lvN3hhYlp1VWpXMHBMUTRNby82ZEFw\n" +
					"dTZMaVRwNy9uSzY3cVJYQ3VDUlFmN0ZMCkxoWGI1WTN3aC9OU2RwTUIvckRseVFz\n" +
					"QjhnZlhLR1kvMTFqdjhXeUZIb2UzeTRBcVA2VEZBZ01CQUFFPQotLS0tLUVORCBS\n" +
					"U0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBV\n" +
					"QkxJQyBLRVktLS0tLQpNSUdKQW9HQkFKZ3pCelkxN3NvcTVEenB3MEJsd3N0UFZY\n" +
					"b1IzYjh0MkhlNVY0WStvY0lYZmRUdEN2L2dqMEtzClRnVnc2Qjd1bklPV01WdHRE\n" +
					"cm9UYnBzZkJIbXB6WTJ0K2pEZFJ4bXNrTm1MM1JvZEhuVUlpcnhGdXdrSXZIT28K\n" +
					"eHAwK0hJanNJalMvNDFRbFhmQ3RkMDQ3RWhHdjErSDVwTVUvR1hWWGo3Q3JOZ0J2\n" +
					"UmlEREFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KCmludHJv\n" +
					"ZHVjdGlvbi1wb2ludCB3aWNuNDVudG9ic282MnNtbm94emt4Y3hlcmx5MmN6cwpp\n" +
					"cC1hZGRyZXNzIDE5Mi40Mi4xMTUuMTAxCm9uaW9uLXBvcnQgOTAwMwpvbmlvbi1r\n" +
					"ZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUwzbE8w\n" +
					"ak5kOWFTVS93aFpmUFpPNGIxaGV3dnlvMFdFc1dxdlJTSkFwS0cwV2doMXc3QjY5\n" +
					"d3kKclBOOWMrbG9rZFZWaHBPSXlxNWhLbnRhdHJ1c0lVTExkaCs0NGVBSTlyUTlM\n" +
					"UFRhZlB5dGVaQTE0TDF5bFZ3ZwpUVFB2bkRZSk9Ib3Zjclc0NVFvNXpoUFBqOGxR\n" +
					"b3p2a2psbURqNFdiUGR4V3NZZjdQYmJWQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBV\n" +
					"QkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMg\n" +
					"S0VZLS0tLS0KTUlHSkFvR0JBTm9CbkI1NndCenhkRGc2ZmdtUFkyZmlpVlhySEFP\n" +
					"aHNGYUduNFRKQVptQ1JtWlBaRGlaSGU3Zwp0QUE0ZXBDelZEYTlzYTgzNEU1UjRK\n" +
					"dXpDMFF0S3cyREVOUEVHYUxDellMV3d3b2dCS3ZGTk5wLy9TeEkvOTlyCnhWZmhL\n" +
					"OTJsR1R5U1ZJVFcrVTNjNHVkZDdBb2F4TEhTNWRBV0JLVFIyZTZBVlk3L0lqdWpB\n" +
					"Z01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCgppbnRyb2R1Y3Rp\n" +
					"b24tcG9pbnQgcjIzc2Y2cTI1aG82ZGVrbHlpcDZ1aXVidHZnNnRobnUKaXAtYWRk\n" +
					"cmVzcyAxOTUuMTg5Ljk2LjE0OApvbmlvbi1wb3J0IDQ0Mwpvbmlvbi1rZXkKLS0t\n" +
					"LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1CT3hJK1pxTUFV\n" +
					"OWRwY0tpTHI1SVowZzlFOE9oVS9oQW8yVnN2cEo4UmlvYk1EUUpEeXY1SmMKUUVt\n" +
					"Nnk5bUNDaUJYYzZQVEZ4eEEyd3RvWFFZeFFDSkRZN3AyS3pId2YrMlpmNnpBOUxh\n" +
					"YlRXZ2I2NWdkNTFWawp6WlphYjlpMXBjZEFoZ1lHUTUzc28zbm8rYnpYMTZFak9Q\n" +
					"QmJTMUg3SHNuMmNyS09RM1AzQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBL\n" +
					"RVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0KTUlHSkFvR0JBTk1TZ2F5UEJQTmN6Zm55aGRtdS9mTVFvdmVvOVFkaTZaNXR6\n" +
					"cW85a013WWdiU3F1Q3FrWndrOAo4YjZ4WEU5TDQxbHdra0xZZGFJWHZISEZzSGxp\n" +
					"YUc4ZTcxWjhEaUNOcVRpaWhGUVl2NzdvYVMwMnQ2T3YzM3RPCk1BTW5kQjkwbm03\n" +
					"Qmx6aEUrSDA4ZTU0Uk94YkFoaEFNSlVBM1hsQlE4cEZBL21BODM1SXZBZ01CQUFF\n" +
					"PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2lu\n" +
					"dCAzZ2lrcnR6NXo3bG50aHF0d2l5bmRuNGlpaGtmbmRzawppcC1hZGRyZXNzIDE0\n" +
					"MS43MC4xMjUuMTUKb25pb24tcG9ydCA5MDAxCm9uaW9uLWtleQotLS0tLUJFR0lO\n" +
					"IFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBS2NOVnlwMDdkcEhQUEVqR3Z4\n" +
					"ZG83cWNLVjFqTG81UGtPS2dMWVRSQmtnYXFXbEtZOGZjMkVMcgpRbWk0VWJpQ0JH\n" +
					"Z3FqcW5FZkNWdVFwdW1JOCtmRlNWNFBZS3J5cnpUc3I1Ky9XWG1lRjVPNW1NamFI\n" +
					"VnF1VTVxCmlpc1psZnVPcHY2eTVHd3lBRjBUcE1yUUhObXNxMXdRbkdiZ09MUUVr\n" +
					"c3RJL3hMV0JSdVBBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0t\n" +
					"CnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdK\n" +
					"QW9HQkFNY1R6VTlENmROaWpPcUxhTHZmMVQ3V1Q1UnhqZlE3RmlmUmhRemFVazlF\n" +
					"Tlk5OWt2UGYrb3p3Ck9ySW5PbWlGeVdhT3JrTUJIMTg1dUhkTVVtTnlLRExKU3pI\n" +
					"TUxTYjhSYWJKZm5qZ3dlSk9kZnlRMnBQNHBZb0cKZGJnajM3VXoxSDhTOTBqdE56\n" +
					"NEY1Q3VuOVdQS3R4NXoyRHJZcEJKU2JPRGZ5Vko4NldYVkFnTUJBQUU9Ci0tLS0t\n" +
					"RU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IHpvNWVi\n" +
					"NTZ6NmtjcGk2cmVoM3JtYmFwam0yYmhpaGpjCmlwLWFkZHJlc3MgMTc2LjkuMzku\n" +
					"MTk2Cm9uaW9uLXBvcnQgOTAwMQpvbmlvbi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVC\n" +
					"TElDIEtFWS0tLS0tCk1JR0pBb0dCQU1UQm9IbmFxY0tSSmx5MWJVVktFVlEyT0hn\n" +
					"Y3RnVnFJaDlhb0NVUjRyR3ZlenBnS1V4UjN5MkEKMG5uc2JRVFlwUm11cStJTThO\n" +
					"Z2JtRnRUdVdjMVlqN1RyV2dURjM1dS82Sm5sbjVmMnkwam9RM0krQW5sWVRUMAox\n" +
					"YjNucTBVRXpmZGdNMlRmZDZjbWVHSjdQdEhvT09pdlRGZ1R1WUw3UVRDZlNxOS9F\n" +
					"cDAvQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNl\n" +
					"LWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBSjV1\n" +
					"YmhRMFNsaUlnOStiOXM3VDdveERSUThpckhpUmJIeU1xUWxnTy9XcHRVRzBpaEVR\n" +
					"ZmVKMQppNi9EMmNTejl2WGlaMWhGQXVLSUVNWkpCZEd1bmpqYWdKbnB6WklZeGRy\n" +
					"V1BaSk83Q2JQMUJXMFFieVkrMW9YCjFLeWc3MHdybHlFVHpCMjhET20vdTBPaC9p\n" +
					"dTQ5OTFmeGVyOFdaQlNHT0M2WjRrN0lrQWpBZ01CQUFFPQotLS0tLUVORCBSU0Eg\n" +
					"UFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2ludCB4b2J0MzI0aWZsNGt6\n" +
					"YWdjeXo2M2ZsY3BvYWptd2VscgppcC1hZGRyZXNzIDM3LjE4Ny45Ni43OApvbmlv\n" +
					"bi1wb3J0IDkwMDEKb25pb24ta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVkt\n" +
					"LS0tLQpNSUdKQW9HQkFNVkpZOEcyUzVZWnRHVy9UVDB2TVhXV2p6Z3Vhdm85M2lm\n" +
					"SWVNRzVQZ0FjcEZ1enVKUmRCT0xpCmdMYnJsU3pRQ28rSVhoQ2plOWw1d3M4ZXpG\n" +
					"L2hUSm03RzVSZ3RHMEtuOW5ScTBGL0tZTWhqNkQyNmxhYXVGMk0KMEhJNmxpUGd0\n" +
					"ejlHYUZ6bXNUOFJFdFpmRzBkTytrWWh5TXhaT2N5V3EvYzdiOXJxZTNvM0FnTUJB\n" +
					"QUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0t\n" +
					"LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU5GM04rRGd3M09s\n" +
					"dzFtSE85Sk9kMllqczA5T2VKVk1COWxCQzc1Q0dPd3NBOUtvajByMVRmUTQKemt1\n" +
					"anNYYnk5b29kQWV6bDNMOUFpekZleS9kSnJOLzdGaXQreFdYdU1pSU04bkl6Q2ds\n" +
					"RjdndW8ySW9tcEpicApDT1dFY1U0Y21MSk1GWTVLc29RNU80NkEwc0tUNmJaaThG\n" +
					"N1hyeGx3UlRUcFZOck0wNGlqQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBL\n" +
					"RVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQgeXFrcGZkNnN4M2F2a21iZWZnbnRk\n" +
					"dmhoZTI3bHJ6NGkKaXAtYWRkcmVzcyAxODguMTM4LjExMi42MApvbmlvbi1wb3J0\n" +
					"IDE1MjEKb25pb24ta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpN\n" +
					"SUdKQW9HQkFQRVU3WUJZMmpRUURubHVJWjBGWElQdnd4eCt5SksrU203WDV6Q09v\n" +
					"Q1NCSlFJdFRZNVB5a1lmCm04ZDI3OWlDY082T0VkUkU5bnhITktRQWI4VVBaNFZJ\n" +
					"a3hJTVBLSDJLblJUeFAvQmx4ZHR2K2J1K3NISEtFUnEKMlVlZFVOT1U5bXFDOTkz\n" +
					"bXpYQjd6OE95enVBUGw1NXljeEF2YVo1ZndOVXdLL3ZGeVlydEFnTUJBQUU9Ci0t\n" +
					"LS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJ\n" +
					"TiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUxRWVdxS0lmRnRXT0tKZmt4\n" +
					"VzcvU3EzZkxpaWwzVGhSSnFrbjVwVC9OMDZyQ1BBNXlUOTRYTjgKU0NuU0lDcmFv\n" +
					"a3hxcjY5cnFvOWhEOXFhNWdzOGhScWhCVE50UmI3dFJxZ0pnT1hpRFJBRnp4WVp3\n" +
					"dmFaT21pZwpNZkdQazhOTXVSV1dieW5XZkdxVlVqb0w0dy9BK2lpR0NFWEZOSVhj\n" +
					"cnIxN0UzK1FkeHNWQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0t\n" +
					"LQppbnRyb2R1Y3Rpb24tcG9pbnQgMzU1a2MzcTJtYTM0bDdmM2p4d3U2b3RtMmpy\n" +
					"bXVuNHoKaXAtYWRkcmVzcyAxOTUuMTU0LjI1My4yMjYKb25pb24tcG9ydCA0NDMK\n" +
					"b25pb24ta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9H\n" +
					"QkFNQjdYVS8yQkloYkNKS01vU21SeWE2NmdFc2lwcUNqTEdRRzFPbFNvWW94VTA1\n" +
					"MFhFNnlWcGFiCm9PV3h5VjBPbEs1c0lKM1ozYVczdCtrUVQ4Zmo0cXBCNXplaDZX\n" +
					"R1JWY3RtK0c2RVJwRmRUUUcyR1MyODlVUTUKL3doOTY2bnFJWHNKclY3MEprUEw5\n" +
					"RWwyWVFmb00wbmhIeUlyUGE3WVE1U2pIS0hRNlNGdEFnTUJBQUU9Ci0tLS0tRU5E\n" +
					"IFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0Eg\n" +
					"UFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUtSZXFCOEpiaGlGNnJxb01WTXE4OUR4\n" +
					"eVE3V0EwMjVpMXlUQUdCQzlsVHZGNlhaV0tCanNTRmkKajVINTArMEtLbzh5TUY1\n" +
					"ZFRhR3Z3TVdWWUw3NEU1WVA5NTdCLzVtck84WjBzdEREc0QrcUx2Z0JGN1RaanE4\n" +
					"YQo4UWNBdWZXd3VjeGpRTnArWVF3MW5qa0g4SkR2MGxveUVjR0dBWTdPelRRSS8z\n" +
					"dkZqSVpMQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRy\n" +
					"b2R1Y3Rpb24tcG9pbnQgaXlvdzVpa3ptM2Q3dGcyZDJuNW55ZWxsbG9oZXB1anEK\n" +
					"aXAtYWRkcmVzcyA1MS4yNTQuNDUuNDMKb25pb24tcG9ydCA5MDAxCm9uaW9uLWtl\n" +
					"eQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBSzY0TFFF\n" +
					"aGtGSHJuK0REeFRLTWQ0bFlHUUcyNU9YelA2TmV0QnNWTWY0dDVDSWpPVVpZdTVI\n" +
					"NwpTbWhhUkFGK0w4Tk9tOUlWZFJlWGkraysvS2F2dHBvbElVTThUSFAyb1kyTnI5\n" +
					"SUdqcS9PSlk5S3BKWVAxOUpuCmd0MjZwcTNIWnNYMDZlYTZ6Z2ZNNzlWWW5yZnlC\n" +
					"M083ZUlRQ21OSEhYZmhIaE1Ca1VvQmZBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVC\n" +
					"TElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBL\n" +
					"RVktLS0tLQpNSUdKQW9HQkFNTkUzUlllQWE2alBiOWxaV0NlRUMzaWJJZU1HeTkw\n" +
					"VnBwTXdocFVTUWlWYzBrMUQ1TzFaNngrCnRPMVJULzBndll1Z2Z0ZzI1SXQ4TTJq\n" +
					"ZVBFY1FWT3U2UkZrNnN4amN5WERGcDVrK1V1VEVKeFFxTjlqSHJnRnAKSjFnL0hS\n" +
					"TE9kdXVQSjBNdzNYYTU4VU5zbmZ0R254aFdGVWdBaUQ3dStxTG1jUFMyMGtJQkFn\n" +
					"TUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9u\n" +
					"LXBvaW50IGRvcDJ6NHM2YzdqZzRtZDZ1N2gycHZjdndmY2xhbXhmCmlwLWFkZHJl\n" +
					"c3MgODIuOTQuMjUxLjIyNwpvbmlvbi1wb3J0IDQ0Mwpvbmlvbi1rZXkKLS0tLS1C\n" +
					"RUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUxHSm0wblJJZnNDU3lD\n" +
					"L05rMGNIQy9pRGF3bXBaQXQ0bUJ0QW9UU1Riak5Gdm5KR2NGUmFlUlYKYXFDQ2Np\n" +
					"YUZ4cmhZcmtmaUVJY1YxaGRDY0V0UlE0WmUzbVdRMStPOTh0bVVXK3ZJRDYxODg0\n" +
					"L3BiT2txYkZkRQpaVGhva3hFVXgrMkgwN1gxcUFPZWJpajRSNXg0NkVSYkRmZFpJ\n" +
					"aXhXNVp1ajE0Ri85RU5iQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVkt\n" +
					"LS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"TUlHSkFvR0JBUExPM1BnM25IMGJsdURpVDR0aEk2NVE0SlcyWWczbDVvem00Q0Fx\n" +
					"Y1ZVdk1qazhzQzgrWUcydgptdzdOdGZvaEJNTU05ejFNbHIrN0RZbDFDZ3pJaEI4\n" +
					"YkROWFZBZnh1bVh2dHhLR0VqTGtLb0RuVmJsaWlTcXk2CkFTNndabTM3T0o1S3hV\n" +
					"VnpJb0RZTC80aGxHQXVpWktVQjNsMmI5eFptc215WUlUSjAveWxBZ01CQUFFPQot\n" +
					"LS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCg==\n" +
					"-----END MESSAGE-----\n",
				"hsdir5-fingerprint": "-----BEGIN MESSAGE-----\n" +
					"aW50cm9kdWN0aW9uLXBvaW50IGh2M2Z5d2RtemtmdWc2M3dzN3Zjenp2ZmNtamZn\n" +
					"Y3ZyCmlwLWFkZHJlc3MgMTguNDkuNS4zNwpvbmlvbi1wb3J0IDkwNTIKb25pb24t\n" +
					"a2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFLK29v\n" +
					"VHZuM3NHYm9xZ3RkWlkxT1JuL0pNcDlYcFJWekJtNVphOFFmOFhtcVBJeE1oRVhp\n" +
					"V0ZJCkVxQ0Q4ZlVtMmtXRFE2TU1SaFlkOHA5RXhva1d0L0xCVHowMVE0aThkWnJ4\n" +
					"UDRlYWxvdkNjWHN6SU8xbEN4RXgKKzdIRldjcEwrS3FpNEdlNWhZN0VBOWsxWjRD\n" +
					"amZSK1M5Y3BZdUsrWmF5K05lQkNmQ2ZuSkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQ\n" +
					"VUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElD\n" +
					"IEtFWS0tLS0tCk1JR0pBb0dCQUxTUml2eVFGYTdxWm43VXlleEpuTElSODFFYUZY\n" +
					"YmdHT3BhMWxTY0U3N3J2WTN5OXlzajZUWFkKUlBMTUZyamhUZjhZcUgwUUYxOGlj\n" +
					"ZEhTUjk4K2tmV3UxM2dqV0FWVEZMWThtbng3RmV6cEQ0WFJodnFjSHd0QwpaeEsx\n" +
					"cjRlWFdwdDNjYUJEVUlZdHJHVC85OXd2MTdnREZISXhyUENjTXloR25NOGwyZnp4\n" +
					"QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rp\n" +
					"b24tcG9pbnQgamtqNmp6cjVwYnFjMmd5b3F1N2hhamFtbXN6Zm5ld2UKaXAtYWRk\n" +
					"cmVzcyAxOTQuNTkuMjA3LjE5NQpvbmlvbi1wb3J0IDQ0Mwpvbmlvbi1rZXkKLS0t\n" +
					"LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUxRTEUyTEY5blNL\n" +
					"WnBWcTh1ZG5nNTE1N2trY2ttUUtDNjk5SitVcU5hU0VWNnl6NzZLWlJXa3cKSjNn\n" +
					"TjBxNm1DR1VzN2J0TmdBeDV2bGlaME5iSUFZZk5xZkE5Y0Y1bExFckx6dTNuWHF4\n" +
					"Zmp6a3gzNFQ3elZDYQpzUnhPdzh5YmFUU1FsK20zYzlkdjBnUjVzQjlTbnlKa1pY\n" +
					"N21kRzc1eTVhSWdmRzBnQ29CQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBL\n" +
					"RVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0KTUlHSkFvR0JBTFVxTFlQSmZxeDBjZVhJR055RXRGcEVMQ3ROaG9FczZYRktY\n" +
					"VlFjM2IvencwREhoWWZjM0RWTwpjYmIxMXdJY2FSWkJubDZpTU9nS1lqRklKZlZL\n" +
					"dzNWK2lta1ZkTDM0WUJhRndvdjZWWW5sZkpKWjZjV2wxZ25CCjdweGZKR3U0VzZK\n" +
					"K3M2VVo1WFB0dXU3S1N4Y1dJMXFRWEprU1VjTDhhNk5xNFMyb0ZaamRBZ01CQUFF\n" +
					"PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2lu\n" +
					"dCB5dWxxZGVpbjVrbXk2dDJyZmI1aGRuN2ppcmUyaDJuNAppcC1hZGRyZXNzIDIx\n" +
					"My4xNTMuODUuODIKb25pb24tcG9ydCA5OTMKb25pb24ta2V5Ci0tLS0tQkVHSU4g\n" +
					"UlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFPTXZJL0JFVXNaVUlpbmEvWUZX\n" +
					"Z2xpSFdBM0ZDeWUzK0lhSStpbWZrQ24wc2JVYzJrNDJsdDJnCitBTWdHcWg2dkhV\n" +
					"MFdtOGEybjRkQ3UwRFdxUWc0R1dOWXdRY3FYRUhtblhlU002UytIYkNvRy91NWVU\n" +
					"OXE4YUIKMG44TmJFdXZFYXBIYlZkZGQ5Rlh3SzFXeTErUnZxUUxEQ00ycEhUVlF2\n" +
					"bjZJS1dBeXNYMUFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"c2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pB\n" +
					"b0dCQUo3NUtyc012dVJyMm83QmRndUdVM205ZkRpYzhSMVZ2K1BheTY2MktNbDRz\n" +
					"QUxvRlBiS0x3WGUKaHFrYzcyZW5RWVduVm5ybTc5bGU2SUtJNkpjTVZZd21UenZZ\n" +
					"dHRyeVY5VzJkVXA1a1NmWkV0RmVOeFZRb243VgpTcTJXT2JBSjNXaXg5aUNVTEh0\n" +
					"eTNpek45ZlZRY2x1MXloR2RqVzFCRHp5T0UzMlBkeE81QWdNQkFBRT0KLS0tLS1F\n" +
					"TkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQgM2Z5Mmp5\n" +
					"bWJjeXY1dGg3b2pxdm5tYm93YXNzcDJ4a2wKaXAtYWRkcmVzcyAxOTMuMTEuMTE0\n" +
					"LjY5Cm9uaW9uLXBvcnQgOTAwMgpvbmlvbi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVC\n" +
					"TElDIEtFWS0tLS0tCk1JR0pBb0dCQU5sUVlFSXhlNng0SkNzdGFBY01zbWcyZ3dE\n" +
					"Zk5KeHBOVGxxQno4R200L1oyS294TVBVZ3p6b1kKMHpWai9NeGViaXMxdEdCTnVn\n" +
					"SzFaWDNqSnJ6TlNNOUV0N243d09VYnJ4cDZQc2FvRkxvNnhOQlVJSVUrUkQ5Mwpm\n" +
					"THdZZGVQdy9mVlk2M0ROZXlleUlCS0hFTUVwYnJKSWVUWXU1WnV5b3pESXp5c2l2\n" +
					"dzJ0QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNl\n" +
					"LWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBS3ZV\n" +
					"WkxOTldTY29lR0hMU2ZVL2E4SUlYRVVHRkVrRUFKVldzZG51dE1jdzd6R3IxY0NO\n" +
					"M1JWcAorRHJvalJVVFdqNzRnWmd3VW1KUkszRHprVnVjTUZvWkRkUStvaHYvM0ZZ\n" +
					"d3BGNGpxT0FhSWtiLzhrMGJ6a09JClFUdm5wR3VqNk1FNGhUVDcybnpWcVQ1TTR0\n" +
					"RlJZcWlXOWhhZ3dydTR0WFBiczc3VnZxVHJBZ01CQUFFPQotLS0tLUVORCBSU0Eg\n" +
					"UFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2ludCAybWpsY25oeHlqd2Qz\n" +
					"enNrMzV3N3l5aWptZnZvc2o2cQppcC1hZGRyZXNzIDM3LjEyMC4xNjcuMTc1Cm9u\n" +
					"aW9uLXBvcnQgOTkzCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZ\n" +
					"LS0tLS0KTUlHSkFvR0JBTUVQTXNsTmlrQWF2OGtGdkhuQld1cENoZjl2MGs4VjRG\n" +
					"eEE0NklNeHRnWUx5UkorVENsODMvegp3MHZZZGpaaTkxM0Q3ZnpHTGxnNDhiM1Vo\n" +
					"MEZVYzhHL3N6MHBCa1c4MHprc1dkdEJkcHlCNituSUhVdk8zUnAxClBIbWlTZzBq\n" +
					"SG5SbWpQRTFWNGdpUzBtZElIZkZSTmhKYnBINlB5bGppTE05eEozbWR3UFJBZ01C\n" +
					"QUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0t\n" +
					"LS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFPZUVDS1VIQy9C\n" +
					"SW52a1lwU0MyUkpZOEpPV3VPd1plamMrYUh4UVZwUTEwYVZlbmoxWTdyTXdmCmVH\n" +
					"RGgyMjRDNk0vNjVmZVVsNVRybjFZS3ZhbHhrQ3poRFNQckhNV1ZhQ2p3Z0NBNUVn\n" +
					"bERSeWZiaWMvcFFvUVEKZk55cXpGOVBnQVVoZGdQMXhpaGk0WVhkMlBlUjdsZTc4\n" +
					"RUhzK2xoM2RWeW9rRGV4NEZnUkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMg\n" +
					"S0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IHZzeGN1NGFhd2s3bGJieWV2a3Fr\n" +
					"ZnhvazN2dW9sY3RkCmlwLWFkZHJlc3MgMTk1LjE1NC4yNDEuMTI1Cm9uaW9uLXBv\n" +
					"cnQgNDQzCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"TUlHSkFvR0JBTml5MFFBc0M5L2toZHhaV0VDOG9SVVBSSkNiTmNpVkNVZDYxdzQx\n" +
					"RWNzZVRyc1V2aDZzQXJrWgpuK1UvaXVQV1psNGcrSUI1a01hYnhuVTBDUWdpZ3Bl\n" +
					"Ri85MDFMRjJXTGMxL09GSHhrL1ArU2lXZ2VnN09oU2dDCkNJNVhoaW5qbEEyS3Vs\n" +
					"YklUa0tkRXl2OHpPUFQ4KzJtVFAwNmYvTjlEYWFteThreURDK25BZ01CQUFFPQot\n" +
					"LS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVH\n" +
					"SU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMOFJGWmZzenkvTndGbGgz\n" +
					"VzJtWTB0VXBraSs2K1VqTTNBTnNCZjVBYzhIeHdGZWFPSjcvRWl6CmUxNWZVNGZF\n" +
					"aXdBM1RNK1pBZmFwTnNXczhldTZpRVVGZVVWakloQWF0UVJSa2E3RnI1STErakQw\n" +
					"N2xidFlRUGEKOGE5OHhvR2ZLN21mV2JtajV6YXhwdUxNbGJIcm5IdzdRcHJkRFIv\n" +
					"RGI3K253OGgxRStydEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0KaW50cm9kdWN0aW9uLXBvaW50IHAzN3dnbmlmd2dhZzN1a3ZxeWppamVwdDR0\n" +
					"d3AzNnJqCmlwLWFkZHJlc3MgMTM2LjI0My4xMzEuMjkKb25pb24tcG9ydCA5MDAx\n" +
					"Cm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFv\n" +
					"R0JBTHhkcS9tZ0hhQVl5T05zb0tRMWU3ZmluWUE1cEFpRGlCOENHUnRGNk9vWktB\n" +
					"bERDWlczcXdBcgpJMDc2QlJnNmVUWGZheGp5d1lvN3hhYlp1VWpXMHBMUTRNby82\n" +
					"ZEFwdTZMaVRwNy9uSzY3cVJYQ3VDUlFmN0ZMCkxoWGI1WTN3aC9OU2RwTUIvckRs\n" +
					"eVFzQjhnZlhLR1kvMTFqdjhXeUZIb2UzeTRBcVA2VEZBZ01CQUFFPQotLS0tLUVO\n" +
					"RCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNB\n" +
					"IFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFKZ3pCelkxN3NvcTVEenB3MEJsd3N0\n" +
					"UFZYb1IzYjh0MkhlNVY0WStvY0lYZmRUdEN2L2dqMEtzClRnVnc2Qjd1bklPV01W\n" +
					"dHREcm9UYnBzZkJIbXB6WTJ0K2pEZFJ4bXNrTm1MM1JvZEhuVUlpcnhGdXdrSXZI\n" +
					"T28KeHAwK0hJanNJalMvNDFRbFhmQ3RkMDQ3RWhHdjErSDVwTVUvR1hWWGo3Q3JO\n" +
					"Z0J2UmlEREFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KCmlu\n" +
					"dHJvZHVjdGlvbi1wb2ludCB3aWNuNDVudG9ic282MnNtbm94emt4Y3hlcmx5MmN6\n" +
					"cwppcC1hZGRyZXNzIDE5Mi40Mi4xMTUuMTAxCm9uaW9uLXBvcnQgOTAwMwpvbmlv\n" +
					"bi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUwz\n" +
					"bE8wak5kOWFTVS93aFpmUFpPNGIxaGV3dnlvMFdFc1dxdlJTSkFwS0cwV2doMXc3\n" +
					"QjY5d3kKclBOOWMrbG9rZFZWaHBPSXlxNWhLbnRhdHJ1c0lVTExkaCs0NGVBSTly\n" +
					"UTlMUFRhZlB5dGVaQTE0TDF5bFZ3ZwpUVFB2bkRZSk9Ib3Zjclc0NVFvNXpoUFBq\n" +
					"OGxRb3p2a2psbURqNFdiUGR4V3NZZjdQYmJWQWdNQkFBRT0KLS0tLS1FTkQgUlNB\n" +
					"IFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJM\n" +
					"SUMgS0VZLS0tLS0KTUlHSkFvR0JBTm9CbkI1NndCenhkRGc2ZmdtUFkyZmlpVlhy\n" +
					"SEFPaHNGYUduNFRKQVptQ1JtWlBaRGlaSGU3Zwp0QUE0ZXBDelZEYTlzYTgzNEU1\n" +
					"UjRKdXpDMFF0S3cyREVOUEVHYUxDellMV3d3b2dCS3ZGTk5wLy9TeEkvOTlyCnhW\n" +
					"ZmhLOTJsR1R5U1ZJVFcrVTNjNHVkZDdBb2F4TEhTNWRBV0JLVFIyZTZBVlk3L0lq\n" +
					"dWpBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCgppbnRyb2R1\n" +
					"Y3Rpb24tcG9pbnQgcjIzc2Y2cTI1aG82ZGVrbHlpcDZ1aXVidHZnNnRobnUKaXAt\n" +
					"YWRkcmVzcyAxOTUuMTg5Ljk2LjE0OApvbmlvbi1wb3J0IDQ0Mwpvbmlvbi1rZXkK\n" +
					"LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1CT3hJK1px\n" +
					"TUFVOWRwY0tpTHI1SVowZzlFOE9oVS9oQW8yVnN2cEo4UmlvYk1EUUpEeXY1SmMK\n" +
					"UUVtNnk5bUNDaUJYYzZQVEZ4eEEyd3RvWFFZeFFDSkRZN3AyS3pId2YrMlpmNnpB\n" +
					"OUxhYlRXZ2I2NWdkNTFWawp6WlphYjlpMXBjZEFoZ1lHUTUzc28zbm8rYnpYMTZF\n" +
					"ak9QQmJTMUg3SHNuMmNyS09RM1AzQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJ\n" +
					"QyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZ\n" +
					"LS0tLS0KTUlHSkFvR0JBTk1TZ2F5UEJQTmN6Zm55aGRtdS9mTVFvdmVvOVFkaTZa\n" +
					"NXR6cW85a013WWdiU3F1Q3FrWndrOAo4YjZ4WEU5TDQxbHdra0xZZGFJWHZISEZz\n" +
					"SGxpYUc4ZTcxWjhEaUNOcVRpaWhGUVl2NzdvYVMwMnQ2T3YzM3RPCk1BTW5kQjkw\n" +
					"bm03Qmx6aEUrSDA4ZTU0Uk94YkFoaEFNSlVBM1hsQlE4cEZBL21BODM1SXZBZ01C\n" +
					"QUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1w\n" +
					"b2ludCAzZ2lrcnR6NXo3bG50aHF0d2l5bmRuNGlpaGtmbmRzawppcC1hZGRyZXNz\n" +
					"IDE0MS43MC4xMjUuMTUKb25pb24tcG9ydCA5MDAxCm9uaW9uLWtleQotLS0tLUJF\n" +
					"R0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBS2NOVnlwMDdkcEhQUEVq\n" +
					"R3Z4ZG83cWNLVjFqTG81UGtPS2dMWVRSQmtnYXFXbEtZOGZjMkVMcgpRbWk0VWJp\n" +
					"Q0JHZ3FqcW5FZkNWdVFwdW1JOCtmRlNWNFBZS3J5cnpUc3I1Ky9XWG1lRjVPNW1N\n" +
					"amFIVnF1VTVxCmlpc1psZnVPcHY2eTVHd3lBRjBUcE1yUUhObXNxMXdRbkdiZ09M\n" +
					"UUVrc3RJL3hMV0JSdVBBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0t\n" +
					"LS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpN\n" +
					"SUdKQW9HQkFNY1R6VTlENmROaWpPcUxhTHZmMVQ3V1Q1UnhqZlE3RmlmUmhRemFV\n" +
					"azlFTlk5OWt2UGYrb3p3Ck9ySW5PbWlGeVdhT3JrTUJIMTg1dUhkTVVtTnlLRExK\n" +
					"U3pITUxTYjhSYWJKZm5qZ3dlSk9kZnlRMnBQNHBZb0cKZGJnajM3VXoxSDhTOTBq\n" +
					"dE56NEY1Q3VuOVdQS3R4NXoyRHJZcEJKU2JPRGZ5Vko4NldYVkFnTUJBQUU9Ci0t\n" +
					"LS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n" +
					"-----END MESSAGE-----\n",
				"hsdir6-fingerprint": "-----BEGIN MESSAGE-----\n" +
					"aW50cm9kdWN0aW9uLXBvaW50IHpvNWViNTZ6NmtjcGk2cmVoM3JtYmFwam0yYmhp\n" +
					"aGpjCmlwLWFkZHJlc3MgMTc2LjkuMzkuMTk2Cm9uaW9uLXBvcnQgOTAwMQpvbmlv\n" +
					"bi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU1U\n" +
					"Qm9IbmFxY0tSSmx5MWJVVktFVlEyT0hnY3RnVnFJaDlhb0NVUjRyR3ZlenBnS1V4\n" +
					"UjN5MkEKMG5uc2JRVFlwUm11cStJTThOZ2JtRnRUdVdjMVlqN1RyV2dURjM1dS82\n" +
					"Sm5sbjVmMnkwam9RM0krQW5sWVRUMAoxYjNucTBVRXpmZGdNMlRmZDZjbWVHSjdQ\n" +
					"dEhvT09pdlRGZ1R1WUw3UVRDZlNxOS9FcDAvQWdNQkFBRT0KLS0tLS1FTkQgUlNB\n" +
					"IFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJM\n" +
					"SUMgS0VZLS0tLS0KTUlHSkFvR0JBSjV1YmhRMFNsaUlnOStiOXM3VDdveERSUThp\n" +
					"ckhpUmJIeU1xUWxnTy9XcHRVRzBpaEVRZmVKMQppNi9EMmNTejl2WGlaMWhGQXVL\n" +
					"SUVNWkpCZEd1bmpqYWdKbnB6WklZeGRyV1BaSk83Q2JQMUJXMFFieVkrMW9YCjFL\n" +
					"eWc3MHdybHlFVHpCMjhET20vdTBPaC9pdTQ5OTFmeGVyOFdaQlNHT0M2WjRrN0lr\n" +
					"QWpBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVj\n" +
					"dGlvbi1wb2ludCB4b2J0MzI0aWZsNGt6YWdjeXo2M2ZsY3BvYWptd2VscgppcC1h\n" +
					"ZGRyZXNzIDM3LjE4Ny45Ni43OApvbmlvbi1wb3J0IDkwMDEKb25pb24ta2V5Ci0t\n" +
					"LS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNVkpZOEcyUzVZ\n" +
					"WnRHVy9UVDB2TVhXV2p6Z3Vhdm85M2lmSWVNRzVQZ0FjcEZ1enVKUmRCT0xpCmdM\n" +
					"YnJsU3pRQ28rSVhoQ2plOWw1d3M4ZXpGL2hUSm03RzVSZ3RHMEtuOW5ScTBGL0tZ\n" +
					"TWhqNkQyNmxhYXVGMk0KMEhJNmxpUGd0ejlHYUZ6bXNUOFJFdFpmRzBkTytrWWh5\n" +
					"TXhaT2N5V3EvYzdiOXJxZTNvM0FnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMg\n" +
					"S0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0t\n" +
					"LS0tCk1JR0pBb0dCQU5GM04rRGd3M09sdzFtSE85Sk9kMllqczA5T2VKVk1COWxC\n" +
					"Qzc1Q0dPd3NBOUtvajByMVRmUTQKemt1anNYYnk5b29kQWV6bDNMOUFpekZleS9k\n" +
					"SnJOLzdGaXQreFdYdU1pSU04bkl6Q2dsRjdndW8ySW9tcEpicApDT1dFY1U0Y21M\n" +
					"Sk1GWTVLc29RNU80NkEwc0tUNmJaaThGN1hyeGx3UlRUcFZOck0wNGlqQWdNQkFB\n" +
					"RT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9p\n" +
					"bnQgeXFrcGZkNnN4M2F2a21iZWZnbnRkdmhoZTI3bHJ6NGkKaXAtYWRkcmVzcyAx\n" +
					"ODguMTM4LjExMi42MApvbmlvbi1wb3J0IDE1MjEKb25pb24ta2V5Ci0tLS0tQkVH\n" +
					"SU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFQRVU3WUJZMmpRUURubHVJ\n" +
					"WjBGWElQdnd4eCt5SksrU203WDV6Q09vQ1NCSlFJdFRZNVB5a1lmCm04ZDI3OWlD\n" +
					"Y082T0VkUkU5bnhITktRQWI4VVBaNFZJa3hJTVBLSDJLblJUeFAvQmx4ZHR2K2J1\n" +
					"K3NISEtFUnEKMlVlZFVOT1U5bXFDOTkzbXpYQjd6OE95enVBUGw1NXljeEF2YVo1\n" +
					"ZndOVXdLL3ZGeVlydEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0t\n" +
					"LS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1J\n" +
					"R0pBb0dCQUxRWVdxS0lmRnRXT0tKZmt4VzcvU3EzZkxpaWwzVGhSSnFrbjVwVC9O\n" +
					"MDZyQ1BBNXlUOTRYTjgKU0NuU0lDcmFva3hxcjY5cnFvOWhEOXFhNWdzOGhScWhC\n" +
					"VE50UmI3dFJxZ0pnT1hpRFJBRnp4WVp3dmFaT21pZwpNZkdQazhOTXVSV1dieW5X\n" +
					"ZkdxVlVqb0w0dy9BK2lpR0NFWEZOSVhjcnIxN0UzK1FkeHNWQWdNQkFBRT0KLS0t\n" +
					"LS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQgMzU1\n" +
					"a2MzcTJtYTM0bDdmM2p4d3U2b3RtMmpybXVuNHoKaXAtYWRkcmVzcyAxOTUuMTU0\n" +
					"LjI1My4yMjYKb25pb24tcG9ydCA0NDMKb25pb24ta2V5Ci0tLS0tQkVHSU4gUlNB\n" +
					"IFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNQjdYVS8yQkloYkNKS01vU21SeWE2\n" +
					"NmdFc2lwcUNqTEdRRzFPbFNvWW94VTA1MFhFNnlWcGFiCm9PV3h5VjBPbEs1c0lK\n" +
					"M1ozYVczdCtrUVQ4Zmo0cXBCNXplaDZXR1JWY3RtK0c2RVJwRmRUUUcyR1MyODlV\n" +
					"UTUKL3doOTY2bnFJWHNKclY3MEprUEw5RWwyWVFmb00wbmhIeUlyUGE3WVE1U2pI\n" +
					"S0hRNlNGdEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2Vy\n" +
					"dmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dC\n" +
					"QUtSZXFCOEpiaGlGNnJxb01WTXE4OUR4eVE3V0EwMjVpMXlUQUdCQzlsVHZGNlha\n" +
					"V0tCanNTRmkKajVINTArMEtLbzh5TUY1ZFRhR3Z3TVdWWUw3NEU1WVA5NTdCLzVt\n" +
					"ck84WjBzdEREc0QrcUx2Z0JGN1RaanE4YQo4UWNBdWZXd3VjeGpRTnArWVF3MW5q\n" +
					"a0g4SkR2MGxveUVjR0dBWTdPelRRSS8zdkZqSVpMQWdNQkFBRT0KLS0tLS1FTkQg\n" +
					"UlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24tcG9pbnQgaXlvdzVpa3pt\n" +
					"M2Q3dGcyZDJuNW55ZWxsbG9oZXB1anEKaXAtYWRkcmVzcyA1MS4yNTQuNDUuNDMK\n" +
					"b25pb24tcG9ydCA5MDAxCm9uaW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMg\n" +
					"S0VZLS0tLS0KTUlHSkFvR0JBSzY0TFFFaGtGSHJuK0REeFRLTWQ0bFlHUUcyNU9Y\n" +
					"elA2TmV0QnNWTWY0dDVDSWpPVVpZdTVINwpTbWhhUkFGK0w4Tk9tOUlWZFJlWGkr\n" +
					"aysvS2F2dHBvbElVTThUSFAyb1kyTnI5SUdqcS9PSlk5S3BKWVAxOUpuCmd0MjZw\n" +
					"cTNIWnNYMDZlYTZ6Z2ZNNzlWWW5yZnlCM083ZUlRQ21OSEhYZmhIaE1Ca1VvQmZB\n" +
					"Z01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5\n" +
					"Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFNTkUzUlll\n" +
					"QWE2alBiOWxaV0NlRUMzaWJJZU1HeTkwVnBwTXdocFVTUWlWYzBrMUQ1TzFaNngr\n" +
					"CnRPMVJULzBndll1Z2Z0ZzI1SXQ4TTJqZVBFY1FWT3U2UkZrNnN4amN5WERGcDVr\n" +
					"K1V1VEVKeFFxTjlqSHJnRnAKSjFnL0hSTE9kdXVQSjBNdzNYYTU4VU5zbmZ0R254\n" +
					"aFdGVWdBaUQ3dStxTG1jUFMyMGtJQkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJM\n" +
					"SUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IGRvcDJ6NHM2YzdqZzRtZDZ1\n" +
					"N2gycHZjdndmY2xhbXhmCmlwLWFkZHJlc3MgODIuOTQuMjUxLjIyNwpvbmlvbi1w\n" +
					"b3J0IDQ0Mwpvbmlvbi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0t\n" +
					"Ck1JR0pBb0dCQUxHSm0wblJJZnNDU3lDL05rMGNIQy9pRGF3bXBaQXQ0bUJ0QW9U\n" +
					"U1Riak5Gdm5KR2NGUmFlUlYKYXFDQ2NpYUZ4cmhZcmtmaUVJY1YxaGRDY0V0UlE0\n" +
					"WmUzbVdRMStPOTh0bVVXK3ZJRDYxODg0L3BiT2txYkZkRQpaVGhva3hFVXgrMkgw\n" +
					"N1gxcUFPZWJpajRSNXg0NkVSYkRmZFpJaXhXNVp1ajE0Ri85RU5iQWdNQkFBRT0K\n" +
					"LS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJF\n" +
					"R0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBUExPM1BnM25IMGJsdURp\n" +
					"VDR0aEk2NVE0SlcyWWczbDVvem00Q0FxY1ZVdk1qazhzQzgrWUcydgptdzdOdGZv\n" +
					"aEJNTU05ejFNbHIrN0RZbDFDZ3pJaEI4YkROWFZBZnh1bVh2dHhLR0VqTGtLb0Ru\n" +
					"VmJsaWlTcXk2CkFTNndabTM3T0o1S3hVVnpJb0RZTC80aGxHQXVpWktVQjNsMmI5\n" +
					"eFptc215WUlUSjAveWxBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0t\n" +
					"LS0tCmludHJvZHVjdGlvbi1wb2ludCBodjNmeXdkbXprZnVnNjN3czd2Y3p6dmZj\n" +
					"bWpmZ2N2cgppcC1hZGRyZXNzIDE4LjQ5LjUuMzcKb25pb24tcG9ydCA5MDUyCm9u\n" +
					"aW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JB\n" +
					"Sytvb1R2bjNzR2JvcWd0ZFpZMU9Sbi9KTXA5WHBSVnpCbTVaYThRZjhYbXFQSXhN\n" +
					"aEVYaVdGSQpFcUNEOGZVbTJrV0RRNk1NUmhZZDhwOUV4b2tXdC9MQlR6MDFRNGk4\n" +
					"ZFpyeFA0ZWFsb3ZDY1hzeklPMWxDeEV4Cis3SEZXY3BMK0txaTRHZTVoWTdFQTlr\n" +
					"MVo0Q2pmUitTOWNwWXVLK1pheStOZUJDZkNmbkpBZ01CQUFFPQotLS0tLUVORCBS\n" +
					"U0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBV\n" +
					"QkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMU1JpdnlRRmE3cVpuN1V5ZXhKbkxJUjgx\n" +
					"RWFGWGJnR09wYTFsU2NFNzdydlkzeTl5c2o2VFhZClJQTE1GcmpoVGY4WXFIMFFG\n" +
					"MThpY2RIU1I5OCtrZld1MTNnaldBVlRGTFk4bW54N0ZlenBENFhSaHZxY0h3dEMK\n" +
					"WnhLMXI0ZVhXcHQzY2FCRFVJWXRyR1QvOTl3djE3Z0RGSEl4clBDY015aEduTThs\n" +
					"MmZ6eEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9k\n" +
					"dWN0aW9uLXBvaW50IGprajZqenI1cGJxYzJneW9xdTdoYWphbW1zemZuZXdlCmlw\n" +
					"LWFkZHJlc3MgMTk0LjU5LjIwNy4xOTUKb25pb24tcG9ydCA0NDMKb25pb24ta2V5\n" +
					"Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFMUUxFMkxG\n" +
					"OW5TS1pwVnE4dWRuZzUxNTdra2NrbVFLQzY5OUorVXFOYVNFVjZ5ejc2S1pSV2t3\n" +
					"CkozZ04wcTZtQ0dVczdidE5nQXg1dmxpWjBOYklBWWZOcWZBOWNGNWxMRXJMenUz\n" +
					"blhxeGZqemt4MzRUN3pWQ2EKc1J4T3c4eWJhVFNRbCttM2M5ZHYwZ1I1c0I5U255\n" +
					"SmtaWDdtZEc3NXk1YUlnZkcwZ0NvQkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJM\n" +
					"SUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtF\n" +
					"WS0tLS0tCk1JR0pBb0dCQUxVcUxZUEpmcXgwY2VYSUdOeUV0RnBFTEN0TmhvRXM2\n" +
					"WEZLWFZRYzNiL3p3MERIaFlmYzNEVk8KY2JiMTF3SWNhUlpCbmw2aU1PZ0tZakZJ\n" +
					"SmZWS3czVitpbWtWZEwzNFlCYUZ3b3Y2VllubGZKSlo2Y1dsMWduQgo3cHhmSkd1\n" +
					"NFc2SitzNlVaNVhQdHV1N0tTeGNXSTFxUVhKa1NVY0w4YTZOcTRTMm9GWmpkQWdN\n" +
					"QkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rpb24t\n" +
					"cG9pbnQgeXVscWRlaW41a215NnQycmZiNWhkbjdqaXJlMmgybjQKaXAtYWRkcmVz\n" +
					"cyAyMTMuMTUzLjg1LjgyCm9uaW9uLXBvcnQgOTkzCm9uaW9uLWtleQotLS0tLUJF\n" +
					"R0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBT012SS9CRVVzWlVJaW5h\n" +
					"L1lGV2dsaUhXQTNGQ3llMytJYUkraW1ma0NuMHNiVWMyazQybHQyZworQU1nR3Fo\n" +
					"NnZIVTBXbThhMm40ZEN1MERXcVFnNEdXTll3UWNxWEVIbW5YZVNNNlMrSGJDb0cv\n" +
					"dTVlVDlxOGFCCjBuOE5iRXV2RWFwSGJWZGRkOUZYd0sxV3kxK1J2cVFMRENNMnBI\n" +
					"VFZRdm42SUtXQXlzWDFBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0t\n" +
					"LS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpN\n" +
					"SUdKQW9HQkFKNzVLcnNNdnVScjJvN0JkZ3VHVTNtOWZEaWM4UjFWditQYXk2NjJL\n" +
					"TWw0c0FMb0ZQYktMd1hlCmhxa2M3MmVuUVlXblZucm03OWxlNklLSTZKY01WWXdt\n" +
					"VHp2WXR0cnlWOVcyZFVwNWtTZlpFdEZlTnhWUW9uN1YKU3EyV09iQUozV2l4OWlD\n" +
					"VUxIdHkzaXpOOWZWUWNsdTF5aEdkalcxQkR6eU9FMzJQZHhPNUFnTUJBQUU9Ci0t\n" +
					"LS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50IDNm\n" +
					"eTJqeW1iY3l2NXRoN29qcXZubWJvd2Fzc3AyeGtsCmlwLWFkZHJlc3MgMTkzLjEx\n" +
					"LjExNC42OQpvbmlvbi1wb3J0IDkwMDIKb25pb24ta2V5Ci0tLS0tQkVHSU4gUlNB\n" +
					"IFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFObFFZRUl4ZTZ4NEpDc3RhQWNNc21n\n" +
					"Mmd3RGZOSnhwTlRscUJ6OEdtNC9aMktveE1QVWd6em9ZCjB6VmovTXhlYmlzMXRH\n" +
					"Qk51Z0sxWlgzakpyek5TTTlFdDduN3dPVWJyeHA2UHNhb0ZMbzZ4TkJVSUlVK1JE\n" +
					"OTMKZkx3WWRlUHcvZlZZNjNETmV5ZXlJQktIRU1FcGJySkllVFl1NVp1eW96REl6\n" +
					"eXNpdncydEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0Kc2Vy\n" +
					"dmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dC\n" +
					"QUt2VVpMTk5XU2NvZUdITFNmVS9hOElJWEVVR0ZFa0VBSlZXc2RudXRNY3c3ekdy\n" +
					"MWNDTjNSVnAKK0Ryb2pSVVRXajc0Z1pnd1VtSlJLM0R6a1Z1Y01Gb1pEZFErb2h2\n" +
					"LzNGWXdwRjRqcU9BYUlrYi84azBiemtPSQpRVHZucEd1ajZNRTRoVFQ3Mm56VnFU\n" +
					"NU00dEZSWXFpVzloYWd3cnU0dFhQYnM3N1Z2cVRyQWdNQkFBRT0KLS0tLS1FTkQg\n" +
					"UlNBIFBVQkxJQyBLRVktLS0tLQo=\n" +
					"-----END MESSAGE-----\n",
			},
		},
		{
			"failure generating descriptor",
			&MockController{},
			hsdirFetcher,
			[]descriptor.HiddenServiceDescriptor{*backendDescriptorLong1, *backendDescriptorLong2},
			func() *rsa.PrivateKey {
				pri := *privateKey
				pri.E = 0
				return &pri
			}(),
			errors.New("failed to generate descriptor: failed to sign descriptor: rsa: internal error"),
			nil,
		},
		{
			"failure calculating responsible HSDirs",
			&MockController{},
			&MockHSDirFetcher{
				returnErr: errors.New("test error"),
			},
			[]descriptor.HiddenServiceDescriptor{*backendDescriptorLong1, *backendDescriptorLong2},
			privateKey,
			errors.New("failed to calculate responsible HSDirs: test error"),
			nil,
		},
		{
			"failure posting descriptor",
			&MockController{
				ReturnedErr: errors.New("test error"),
			},
			hsdirFetcher,
			[]descriptor.HiddenServiceDescriptor{*backendDescriptorLong1, *backendDescriptorLong2},
			privateKey,
			nil,
			nil,
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			onion, err := NewOnion(tt.controller, []string{}, publicKey, tt.privateKey, tt.hsdirFetcher, logger, mockTime, 0)
			if err != nil {
				t.Fatal("failed to create new onion")
			}

			err = onion.multiDescriptorGenerateAndPublish(tt.backendDescriptors)
			if !reflect.DeepEqual(err, tt.expectedErr) {
				t.Fatalf("expected %v got %v", tt.expectedErr, err)
			}

			for hsdir, postedDescriptor := range tt.controller.PostedDescriptors {
				parsedDescriptor, err := descriptor.ParseHiddenServiceDescriptor(postedDescriptor)
				if err != nil {
					t.Fatal("failed to parse descriptor")
				}

				expectedDescriptor, ok := tt.expectedDescriptorsIntrosRaw[hsdir]
				if !ok {
					t.Error("posted descriptor to incorrect hsdir")
				}

				if parsedDescriptor.IntroductionPointsRaw != expectedDescriptor {
					t.Errorf("expected %v got %v", expectedDescriptor, parsedDescriptor.IntroductionPointsRaw)
				}
			}
		})
	}
}

//func TestOnion_GetResponsibleHSDirs(t *testing.T) {
//	var conn, err = textproto.Dial("tcp", "localhost:9054")
//	if err != nil {
//		t.Fatalf("dial error: %v", err)
//	}
//	defer conn.Close()
//
//	var controller = control.NewConn(conn)
//	if err = controller.Authenticate(""); err != nil {
//		t.Fatalf("authentication error: %v", err)
//	}
//
//	var descriptorID = []byte{}
//	descriptorID, err = common.CalculateDescriptorID("facebookcorewwwi", time.Now().Unix(), 1, 0, "")
//	if err != nil {
//		t.Fatalf("failed to calculate descriptor ID : %v", err)
//	}
//
//	var got = []descriptor.RouterStatusEntry{}
//	got, err = GetResponsibleHSDirs(string(descriptorID), controller)
//	if err != nil {
//		t.Fatalf("failed to get the responsible hsdirs %v", err)
//	}
//
//	if got == nil {
//		t.Errorf("no hsdirs return")
//	}
//
//	controller.Close()
//	conn.Close()
//}
//
