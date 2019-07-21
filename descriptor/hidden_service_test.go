package descriptor

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/csucu/onionspread/common"
)

var (
	pubKey                     *rsa.PublicKey
	priKey                     *rsa.PrivateKey
	testDescriptorRaw          string
	testRouterStatusEntriesRaw string

	descriptor = &HiddenServiceDescriptor{
		DescriptorID: "g55eugbqhviysu7bi4qzjcru5r4q7wxb",
		Version:      2,
		PermanentKey: "-----BEGIN RSA PUBLIC KEY-----\n" +
			"MIGJAoGBAL4DHCWCCLpASOczBDoXoq0Xj7BH6Ml04egaDBpUDqHwMuGql7Ugcckx\n" +
			"wDm5fgOZCDaFLdTNY14c1abKkYxnBK/TBwapvQ6BYs6eDYZAFFIcCgAKR4cT1B5a\n" +
			"8ZnA7D4wPDEVIKf2qfpwlTk+1VNY/QxHbdV+W8qyRy3tYeusnVVTAgMBAAE=\n" +
			"-----END RSA PUBLIC KEY-----\n",
		SecretID:         "lla5msccdow4h5dfbnwihs63fgb4ve77",
		ProtocolVersions: []int{2, 3},
		IntroductionPoints: []IntroductionPoint{
			{
				Identifier: "6zmzbqr2wal2ynzcn2zk2pnfvdvokxim",
				Address:    net.ParseIP("91.221.119.33"),
				Port:       443,
				OnionKey: "-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAN3LE8fupkoXs9kFuK/V6vQQfCbq4UrQV9DHrOlLv0OWl+WR2uG0Q4/0\n" +
					"8xK/V+girLue8crmsp8h9SJtZiUD/Ch1pCmh1tgPh3qKO8w0Q9LGmDu3RHkufFQ/\n" +
					"eaD4h51W1x5emSeOV+Il1P/PXaEqucLyb+ePXLynMUJy75cd+NoZAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n",
				ServiceKey: "-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAK+ioJHuvNe6IaH/ZU9nOtZXHmaTr/6FCpfE1pqJn1/vBYvIBeEq+m9b\n" +
					"cuCyTD/o6x6WxPqk4u6jTCzVQtph2+wunZ8rjVE2awq66oVfr2hKRZwQKSOjVMMF\n" +
					"sGgEGymm25g/zovNKexwpP+Qe3H3fUoGjEByesREzFHOdMjt25kvAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n",
				Raw: "introduction-point 6zmzbqr2wal2ynzcn2zk2pnfvdvokxim\n" +
					"ip-address 91.221.119.33\nonion-port 443\nonion-key\n" +
					"-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAN3LE8fupkoXs9kFuK/V6vQQfCbq4UrQV9DHrOlLv0OWl+WR2uG0Q4/0\n" +
					"8xK/V+girLue8crmsp8h9SJtZiUD/Ch1pCmh1tgPh3qKO8w0Q9LGmDu3RHkufFQ/\n" +
					"eaD4h51W1x5emSeOV+Il1P/PXaEqucLyb+ePXLynMUJy75cd+NoZAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n" +
					"service-key\n" +
					"-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAK+ioJHuvNe6IaH/ZU9nOtZXHmaTr/6FCpfE1pqJn1/vBYvIBeEq+m9b\n" +
					"cuCyTD/o6x6WxPqk4u6jTCzVQtph2+wunZ8rjVE2awq66oVfr2hKRZwQKSOjVMMF\n" +
					"sGgEGymm25g/zovNKexwpP+Qe3H3fUoGjEByesREzFHOdMjt25kvAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n",
			},
			{
				Identifier: "s5zo7njvhf6jilb2xcae7m2476wqcjby",
				Address:    net.ParseIP("37.153.1.10"),
				Port:       9001,
				OnionKey: "-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAKaM9dC4hd6qo5PUG1rbNLFh1LsZj3leq8qQXh6iPXp2P+hhHPP/DHwi\n" +
					"RacxYZTmImc8oOWJKM/MkTSXuWuCHPH8d4Nv3NDwHwjstlD1zqIKlXzhrtSU4pkR\n" +
					"PrBk1dKv770u/L/XzhtH5BbWQ0oQ2+Xnz5PoIpHLS5NEEoS2fxzRAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n",
				ServiceKey: "-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAL4vDRM8PHebO8p/PVJURuORvUzBdxlerBwzE1grNdPcUn1ooqT8xHaN\n" +
					"y/Wa0N0TEccJxnu1JLl5rWWNA4sTvnFBNuyTQ+AKSLvDKfmlCk5kaGbipETdX5Xd\n" +
					"MBQ8PDreGvVBXDrHPpkTrkEVTDPXTvRzDArMmLDs8k+x7k9Xl4yzAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n",
				Raw: "introduction-point s5zo7njvhf6jilb2xcae7m2476wqcjby\n" +
					"ip-address 37.153.1.10\nonion-port 9001\nonion-key\n" +
					"-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAKaM9dC4hd6qo5PUG1rbNLFh1LsZj3leq8qQXh6iPXp2P+hhHPP/DHwi\n" +
					"RacxYZTmImc8oOWJKM/MkTSXuWuCHPH8d4Nv3NDwHwjstlD1zqIKlXzhrtSU4pkR\n" +
					"PrBk1dKv770u/L/XzhtH5BbWQ0oQ2+Xnz5PoIpHLS5NEEoS2fxzRAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n" +
					"service-key\n" +
					"-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAL4vDRM8PHebO8p/PVJURuORvUzBdxlerBwzE1grNdPcUn1ooqT8xHaN\n" +
					"y/Wa0N0TEccJxnu1JLl5rWWNA4sTvnFBNuyTQ+AKSLvDKfmlCk5kaGbipETdX5Xd\n" +
					"MBQ8PDreGvVBXDrHPpkTrkEVTDPXTvRzDArMmLDs8k+x7k9Xl4yzAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n",
			},
			{
				Identifier: "qrfotswqims6svpcxykscvr3ph7hbffx",
				Address:    net.ParseIP("192.87.28.82"),
				Port:       9001,
				OnionKey: "-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAMJRx82NnUxceZ0MY3jl6n/fspXzR23MmLTKDtBfrC5rM+k/Qgaeygoy\n" +
					"mGyzFjDM9LWMESRA7m+eRfUy0dhczWwgpE6EvzXwNfIXtDz5aysAIehLnOsNSQDx\n" +
					"i1O9D3mWdeZzc6DTbyU/9P0OI0HABPX883on1gpaCWmVCWVegQdzAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n",
				ServiceKey: "-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAL5cccVFdpYoZIi8fnmwYL5sL/iBEUnWWl2lPxYfhL3VD+21AMd/xifB\n" +
					"H3VtT4lqmmWNrA0kgQSPIiEB9NUeHx40Q8ifzILbscRry6gHhUbfM2OkjsoS2odO\n" +
					"afg3g/Obz8hEQ45PCez2m/EQr4RiiNndgPCPtKrbknbMn5kyNIdnAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n",
				Raw: "introduction-point qrfotswqims6svpcxykscvr3ph7hbffx\n" +
					"ip-address 192.87.28.82\n" +
					"onion-port 9001\n" +
					"onion-key\n" +
					"-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAMJRx82NnUxceZ0MY3jl6n/fspXzR23MmLTKDtBfrC5rM+k/Qgaeygoy\n" +
					"mGyzFjDM9LWMESRA7m+eRfUy0dhczWwgpE6EvzXwNfIXtDz5aysAIehLnOsNSQDx\n" +
					"i1O9D3mWdeZzc6DTbyU/9P0OI0HABPX883on1gpaCWmVCWVegQdzAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n" +
					"service-key\n" +
					"-----BEGIN RSA PUBLIC KEY-----\n" +
					"MIGJAoGBAL5cccVFdpYoZIi8fnmwYL5sL/iBEUnWWl2lPxYfhL3VD+21AMd/xifB\n" +
					"H3VtT4lqmmWNrA0kgQSPIiEB9NUeHx40Q8ifzILbscRry6gHhUbfM2OkjsoS2odO\n" +
					"afg3g/Obz8hEQ45PCez2m/EQr4RiiNndgPCPtKrbknbMn5kyNIdnAgMBAAE=\n" +
					"-----END RSA PUBLIC KEY-----\n" +
					"\n",
			},
		},
		Signature: "-----BEGIN SIGNATURE-----\n" +
			"tkYY8ubTltjXeCuT9miUVLHFSb5Vc2I6o6uhg+A0I2kqBHUB27mYn1R2VwGitICq\n" +
			"2Q6lIpu4X5NYEqns8K3OrzjC8JlLtptz4H8DQTrkO3hhNGXLzNNU0ZS9Y0Tw8pw7\n" +
			"DrboUsTEdlIzGXs8xGsbI7bmVY55q+GV1c5fQ3oE9kQ=\n" +
			"-----END SIGNATURE-----\n",
		Published: time.Date(2018, 8, 13, 13, 0, 0, 0, time.UTC),
	}
)

func TestMain(m *testing.M) {
	var err error
	descriptorBytes, err := ioutil.ReadFile("../testdata/desc.txt")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	testDescriptorRaw = string(descriptorBytes)

	routerStatusesBytes, err := ioutil.ReadFile("../testdata/routerEntriesLong.txt")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	testRouterStatusEntriesRaw = string(routerStatusesBytes)

	introductionPointsRawBytes, err := ioutil.ReadFile("../testdata/introductionPointsBlock.pem")
	if err != nil {
		fmt.Printf("TestMain: %v\n", err.Error())
		os.Exit(1)
	}

	descriptor.IntroductionPointsRaw = string(introductionPointsRawBytes)

	pubKey, priKey, err = common.LoadKeysFromFile("../testdata/rsaKey")
	if err != nil {
		fmt.Printf("TestMain: failed to load keys from file: %v\n", err.Error())
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestParseHiddenServiceDescriptor(t *testing.T) {
	t.Parallel()

	var got, err = ParseHiddenServiceDescriptor(testDescriptorRaw)
	if err != nil {
		t.Fatalf("failed to parse hidden service descriptor: %v", err)
	}

	if !reflect.DeepEqual(*descriptor, *got) {
		t.Errorf("expected %#v got %#v", *descriptor, *got)
	}
}

func TestParseIntroductionPoints(t *testing.T) {
	var got, err = parseIntroductionPoints(descriptor.IntroductionPointsRaw)
	if err != nil {
		t.Fatalf("failed to parse introduction points: %v", err.Error())
	}

	if !reflect.DeepEqual(descriptor.IntroductionPoints, got) {
		t.Errorf("expected %#v got %#v", descriptor.IntroductionPoints, got)
	}
}

func TestExtractIntroductionPoints(t *testing.T) {
	t.Parallel()

	var testCases = []struct {
		name                  string
		input                 string
		wantIntroductionPoint *IntroductionPoint
		wantData              string
		wantEOF               bool
	}{
		{
			"first entry",
			"introduction-point 6zmzbqr2wal2ynzcn2zk2pnfvdvokxim\n" +
				"ip-address 91.221.119.33\n" +
				"onion-port 443\n" +
				"onion-key\n" +
				"-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIGJAoGBAN3LE8fupkoXs9kFuK/V6vQQfCbq4UrQV9DHrOlLv0OWl+WR2uG0Q4/0\n" +
				"8xK/V+girLue8crmsp8h9SJtZiUD/Ch1pCmh1tgPh3qKO8w0Q9LGmDu3RHkufFQ/\n" +
				"eaD4h51W1x5emSeOV+Il1P/PXaEqucLyb+ePXLynMUJy75cd+NoZAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----\n" +
				"service-key\n" +
				"-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIGJAoGBAK+ioJHuvNe6IaH/ZU9nOtZXHmaTr/6FCpfE1pqJn1/vBYvIBeEq+m9b\n" +
				"cuCyTD/o6x6WxPqk4u6jTCzVQtph2+wunZ8rjVE2awq66oVfr2hKRZwQKSOjVMMF\n" +
				"sGgEGymm25g/zovNKexwpP+Qe3H3fUoGjEByesREzFHOdMjt25kvAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----\n" +
				"introduction-point s5zo7njvhf6jilb2xcae7m2476wqcjby\n" +
				"ip-address 37.153.1.10\n" +
				"onion-port 9001\n" +
				"onion-key\n" +
				"-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIGJAoGBAKaM9dC4hd6qo5PUG1rbNLFh1LsZj3leq8qQXh6iPXp2P+hhHPP/DHwi\n" +
				"RacxYZTmImc8oOWJKM/MkTSXuWuCHPH8d4Nv3NDwHwjstlD1zqIKlXzhrtSU4pkR\n" +
				"PrBk1dKv770u/L/XzhtH5BbWQ0oQ2+Xnz5PoIpHLS5NEEoS2fxzRAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----\n" +
				"service-key\n" +
				"-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIGJAoGBAL4vDRM8PHebO8p/PVJURuORvUzBdxlerBwzE1grNdPcUn1ooqT8xHaN\n" +
				"y/Wa0N0TEccJxnu1JLl5rWWNA4sTvnFBNuyTQ+AKSLvDKfmlCk5kaGbipETdX5Xd\n" +
				"MBQ8PDreGvVBXDrHPpkTrkEVTDPXTvRzDArMmLDs8k+x7k9Xl4yzAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----\n",
			&descriptor.IntroductionPoints[0],
			"introduction-point s5zo7njvhf6jilb2xcae7m2476wqcjby\n" +
				"ip-address 37.153.1.10\n" +
				"onion-port 9001\n" +
				"onion-key\n" +
				"-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIGJAoGBAKaM9dC4hd6qo5PUG1rbNLFh1LsZj3leq8qQXh6iPXp2P+hhHPP/DHwi\n" +
				"RacxYZTmImc8oOWJKM/MkTSXuWuCHPH8d4Nv3NDwHwjstlD1zqIKlXzhrtSU4pkR\n" +
				"PrBk1dKv770u/L/XzhtH5BbWQ0oQ2+Xnz5PoIpHLS5NEEoS2fxzRAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----\n" +
				"service-key\n" +
				"-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIGJAoGBAL4vDRM8PHebO8p/PVJURuORvUzBdxlerBwzE1grNdPcUn1ooqT8xHaN\n" +
				"y/Wa0N0TEccJxnu1JLl5rWWNA4sTvnFBNuyTQ+AKSLvDKfmlCk5kaGbipETdX5Xd\n" +
				"MBQ8PDreGvVBXDrHPpkTrkEVTDPXTvRzDArMmLDs8k+x7k9Xl4yzAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----\n",

			false,
		},
		{
			"last entry",
			"introduction-point s5zo7njvhf6jilb2xcae7m2476wqcjby\n" +
				"ip-address 37.153.1.10\n" +
				"onion-port 9001\n" +
				"onion-key\n" +
				"-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIGJAoGBAKaM9dC4hd6qo5PUG1rbNLFh1LsZj3leq8qQXh6iPXp2P+hhHPP/DHwi\n" +
				"RacxYZTmImc8oOWJKM/MkTSXuWuCHPH8d4Nv3NDwHwjstlD1zqIKlXzhrtSU4pkR\n" +
				"PrBk1dKv770u/L/XzhtH5BbWQ0oQ2+Xnz5PoIpHLS5NEEoS2fxzRAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----\n" +
				"service-key\n" +
				"-----BEGIN RSA PUBLIC KEY-----\n" +
				"MIGJAoGBAL4vDRM8PHebO8p/PVJURuORvUzBdxlerBwzE1grNdPcUn1ooqT8xHaN\n" +
				"y/Wa0N0TEccJxnu1JLl5rWWNA4sTvnFBNuyTQ+AKSLvDKfmlCk5kaGbipETdX5Xd\n" +
				"MBQ8PDreGvVBXDrHPpkTrkEVTDPXTvRzDArMmLDs8k+x7k9Xl4yzAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----\n",
			&descriptor.IntroductionPoints[1],
			"",
			true,
		},
	}

	for _, tt := range testCases {
		var tt = tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var introductionPoint, data, EOF, err = extractIntroductionPoints(tt.input)
			if err != nil {
				t.Fatalf("failed to extract introduction points: %v", err)
			}

			if !reflect.DeepEqual(*tt.wantIntroductionPoint, *introductionPoint) {
				t.Errorf("expected %#v got %#v", *tt.wantIntroductionPoint, *introductionPoint)
			}

			if tt.wantData != data {
				t.Errorf("expected %v got %v", tt.wantData, data)
			}

			if tt.wantEOF != EOF {
				t.Errorf("expected %v got %v", tt.wantEOF, EOF)
			}
		})
	}
}

func TestParseIntroductionPoint(t *testing.T) {
	t.Parallel()

	var input = "introduction-point 6zmzbqr2wal2ynzcn2zk2pnfvdvokxim\n" +
		"ip-address 91.221.119.33\n" +
		"onion-port 443\n" +
		"onion-key\n" +
		"-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAN3LE8fupkoXs9kFuK/V6vQQfCbq4UrQV9DHrOlLv0OWl+WR2uG0Q4/0\n" +
		"8xK/V+girLue8crmsp8h9SJtZiUD/Ch1pCmh1tgPh3qKO8w0Q9LGmDu3RHkufFQ/\n" +
		"eaD4h51W1x5emSeOV+Il1P/PXaEqucLyb+ePXLynMUJy75cd+NoZAgMBAAE=\n" +
		"-----END RSA PUBLIC KEY-----\n" +
		"service-key\n" +
		"-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAK+ioJHuvNe6IaH/ZU9nOtZXHmaTr/6FCpfE1pqJn1/vBYvIBeEq+m9b\n" +
		"cuCyTD/o6x6WxPqk4u6jTCzVQtph2+wunZ8rjVE2awq66oVfr2hKRZwQKSOjVMMF\n" +
		"sGgEGymm25g/zovNKexwpP+Qe3H3fUoGjEByesREzFHOdMjt25kvAgMBAAE=\n" +
		"-----END RSA PUBLIC KEY-----\n"

	var got, err = parseIntroductionPoint(input)
	if err != nil {
		t.Fatalf("failed to parse hidden service introduction point: %v", err)
	}

	if !reflect.DeepEqual(descriptor.IntroductionPoints[0], *got) {
		t.Errorf("expected %#v got %#v", descriptor.IntroductionPoints[0], *got)
	}
}

func TestCreateIntroductionPointsBloc(t *testing.T) {
	var gotBytes = createIntroductionPointsBloc(descriptor.IntroductionPoints)
	if got := string(gotBytes); !reflect.DeepEqual(descriptor.IntroductionPointsRaw, got) {
		t.Errorf("expected %#v got %#v", descriptor.IntroductionPointsRaw, got)
	}
}

func TestCreatePublicKeyBloc(t *testing.T) {
	var blocBytes, err = createPublicKeyBloc(pubKey)
	if err != nil {
		t.Fatal("failed to create public key bloc")
	}

	if got := string(blocBytes); got != descriptor.PermanentKey {
		t.Errorf("expected %s got %s", descriptor.PermanentKey, got)
	}
}

func TestGenerateDescriptorRaw(t *testing.T) {
	var pubTime = time.Unix(time.Now().Unix()%(60*60), 0)
	var descRaw, err = GenerateDescriptorRaw(descriptor.IntroductionPoints, pubTime, 1, 0,
		"", pubKey, priKey, nil, nil)
	if err != nil {
		t.Fatalf("failed to generate descriptor: %v", err)
	}

	var desc *HiddenServiceDescriptor
	desc, err = ParseHiddenServiceDescriptor(string(descRaw))

	if desc.PermanentKey != descriptor.PermanentKey {
		t.Errorf("expected PermanentKey %s got %s", descriptor.PermanentKey, desc.PermanentKey)
	}

	if !reflect.DeepEqual(desc.IntroductionPoints, descriptor.IntroductionPoints) {
		t.Errorf("expected introduction points %#v got %#v", descriptor.IntroductionPoints, desc.IntroductionPoints)
	}

	if desc.Version != descriptor.Version {
		t.Errorf("expected version %d got %d", descriptor.Version, desc.Version)
	}

	// verify signature
	var h = sha1.New()
	h.Write(descRaw[:bytes.Index(descRaw, []byte("signature"))+10])

	var signatureBlock, rest = pem.Decode([]byte(desc.Signature))
	if signatureBlock == nil || len(rest) < 0 {
		t.Fatal("failed to decode pem encoded signature")
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.Hash(0), h.Sum(nil), signatureBlock.Bytes)
	if err != nil {
		t.Errorf("signature is invalid")
	}
}

//func TestFetchHiddenServiceDescriptor(t *testing.T) {
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
//	var descriptor = &HiddenServiceDescriptor{}
//	descriptor, err = FetchHiddenServiceDescriptor("7ctbljpgkiayaita", "", controller, context.Background())
//	if err != nil {
//		t.Fatalf("failed to fetch descriptor: %v", err)
//	}
//
//	if descriptor == nil {
//		t.Errorf("nil descriptor")
//	}
//
//	controller.Close()
//	conn.Close()
//}
