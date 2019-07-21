package descriptor

/*
	todo:
		- make generator functions methods of descriptor
		- prefix errors with "descriptor"
		- generator functions should probably check for empty inputs etc, and return errors
*/
import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/csucu/onionspread/common"
)

// HiddenServiceDescriptor represents a v2 hidden service descriptor as defined in
// https://github.com/torproject/torspec/blob/master/rend-spec-v2.txt
type HiddenServiceDescriptor struct {
	DescriptorID          string
	Version               int
	PermanentKey          string
	SecretID              string
	Published             time.Time
	ProtocolVersions      []int
	IntroductionPointsRaw string
	IntroductionPoints    []IntroductionPoint
	Signature             string
}

// IntroductionPoint represents a introduction point
type IntroductionPoint struct {
	Identifier string
	Address    net.IP
	Port       int
	OnionKey   string
	ServiceKey string
	Raw        string
}

func ParseHiddenServiceDescriptor(descriptorRaw string) (*HiddenServiceDescriptor, error) {
	var descriptor = &HiddenServiceDescriptor{}
	var lines = strings.Split(descriptorRaw, "\n")
	var err error

	for i, line := range lines {
		var words = strings.Split(line, " ")
		switch words[0] {
		case "rendezvous-service-descriptor":
			descriptor.DescriptorID = words[1]
		case "version":
			descriptor.Version, err = strconv.Atoi(words[1])
		case "permanent-key":
			descriptor.PermanentKey, err = extractEntry("-----END RSA PUBLIC KEY-----", lines[i:])
		case "secret-id-part":
			descriptor.SecretID = words[1]
		case "publication-time":
			descriptor.Published, err = time.Parse("2006-01-02 15:04:05", strings.Join(words[1:], " "))
		case "protocol-versions":
			for _, versionStr := range strings.Split(words[1], ",") {
				var version int
				version, err = strconv.Atoi(versionStr)
				if err != nil {
					return nil, err
				}

				descriptor.ProtocolVersions = append(descriptor.ProtocolVersions, version)
			}
		case "introduction-points":
			descriptor.IntroductionPointsRaw, err = extractEntry("-----END MESSAGE-----", lines[i:])
			descriptor.IntroductionPoints, err = parseIntroductionPoints(descriptor.IntroductionPointsRaw)
		case "signature":
			descriptor.Signature, err = extractEntry("-----END SIGNATURE-----", lines[i:])
		}

		if err != nil {
			return nil, err
		}
	}

	return descriptor, nil
}

// parseIntroductionPoints parses the introduction points block given in a descriptor
func parseIntroductionPoints(data string) ([]IntroductionPoint, error) {
	var introductionPoints []IntroductionPoint

	var block, rest = pem.Decode([]byte(data))
	if len(rest) > 0 {
		return introductionPoints, errors.New("trailing bytes when decoding introduction points PEM")
	}

	var raw = string(block.Bytes)
	var EOF bool
	var err error

	for {
		var introductionPoint *IntroductionPoint
		introductionPoint, raw, EOF, err = extractIntroductionPoints(raw)
		if err != nil {
			return introductionPoints, err
		}

		introductionPoints = append(introductionPoints, *introductionPoint)

		if EOF {
			break
		}
	}

	return introductionPoints, nil
}

// extractIntroductionPoints extracts a single introduction point from the provided raw introduction point block
func extractIntroductionPoints(data string) (*IntroductionPoint, string, bool, error) {
	if len(data) == 0 {
		return nil, data, true, nil
	}

	var start = 0
	if !strings.HasPrefix(data, string("introduction-point")) {
		start = strings.Index(data, string("introduction-point"))
		if start < 0 {
			return nil, data, false, errors.New("cannot find any introduction points")
		}
	}

	var end = strings.Index(data[start:], string("\nintroduction-point "))
	if end >= 0 {
		var introductionPoint, err = parseIntroductionPoint(data[start : start+end+1])
		if err != nil {
			return nil, "", false, err
		}

		return introductionPoint, data[start+end+1:], false, nil
	}

	var introductionPoint, err = parseIntroductionPoint(data[start:])
	if err != nil {
		return nil, "", false, err
	}

	return introductionPoint, "", true, nil
}

// parseIntroductionPoint returns an introduction point object given its raw representation
func parseIntroductionPoint(data string) (*IntroductionPoint, error) {
	var introductionPoint = &IntroductionPoint{}
	var lines = strings.Split(data, "\n")
	var err error

	for i, line := range lines {
		var words = strings.Split(line, " ")

		switch words[0] {
		case "introduction-point":
			introductionPoint.Identifier = words[1]
		case "ip-address":
			introductionPoint.Address = net.ParseIP(words[1])
		case "onion-port":
			introductionPoint.Port, err = strconv.Atoi(words[1])
		case "onion-key":
			introductionPoint.OnionKey, err = extractEntry("-----END RSA PUBLIC KEY-----", lines[i:])
			if err != nil {
				return nil, err
			}
		case "service-key":
			introductionPoint.ServiceKey, err = extractEntry("-----END RSA PUBLIC KEY-----", lines[i:])
		}

		if err != nil {
			return nil, err
		}
	}

	introductionPoint.Raw = data

	return introductionPoint, nil
}

func extractEntry(end string, lines []string) (string, error) {
	var entry = ""
	for _, line := range lines[1:] {
		entry += line
		entry += "\n"

		if strings.Contains(line, end) {
			break
		}
	}

	if entry == "" {
		return "", fmt.Errorf("could not find entry while parsing descriptor")
	}

	return entry, nil
}

// GenerateDescriptorRaw generates a raw signed hidden service descriptor
func GenerateDescriptorRaw(introductionPoints []IntroductionPoint, publishedTime time.Time, replica byte,
	deviation uint8, descriptorCookie string, permanentKey *rsa.PublicKey, privateKey *rsa.PrivateKey, permID []byte, descriptorID []byte) ([]byte, error) {
	var err error
	if permID == nil {
		permID, err = common.CalculatePermanentID(*permanentKey)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate permanent id: %v", err)
		}
	}

	var timeUnix = publishedTime.Unix()
	if descriptorID == nil {
		descriptorID, err = common.CalculateDescriptorID(permID, timeUnix, replica, deviation, descriptorCookie)
		if err != nil {
			return nil, err
		}
	}

	// Public key bloc
	var publicKeyBlock []byte
	publicKeyBlock, err = createPublicKeyBloc(permanentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate publicKeyBlock: %v", err)
	}

	// secret id
	var secretIDPart = common.GetSecretID(permID, timeUnix, descriptorCookie, replica)

	// Introduction point block
	var introBlock = createIntroductionPointsBloc(introductionPoints)

	// Published time
	var formattedTime = time.Unix(timeUnix-timeUnix%(60*60), 0).Format("2006-01-02 15:04:05")

	var b bytes.Buffer
	b.WriteString("rendezvous-service-descriptor ")
	b.Write(bytes.ToLower(descriptorID))
	b.WriteString("\nversion 2\npermanent-key\n")
	b.Write(publicKeyBlock)
	b.WriteString("secret-id-part ")
	b.Write(secretIDPart)
	b.WriteByte('\n')
	b.WriteString("publication-time " + formattedTime + "\n")
	b.WriteString("protocol-versions 2,3\n")
	b.WriteString("introduction-points\n")
	b.Write(introBlock)
	b.WriteString("signature\n")

	// Signature block
	var signatureBlock []byte
	signatureBlock, err = createSignatureBlock(b.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}

	b.Write(signatureBlock)

	return b.Bytes(), nil
}

func createIntroductionPointsBloc(introductionPoints []IntroductionPoint) []byte {
	var introductionPointsRaw []byte
	for _, IntroductionPoint := range introductionPoints {
		introductionPointsRaw = append(introductionPointsRaw, []byte(IntroductionPoint.Raw)...)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "MESSAGE", Bytes: introductionPointsRaw})
}

func createPublicKeyBloc(permanentKey *rsa.PublicKey) ([]byte, error) {
	var der, err = asn1.Marshal(*permanentKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}), nil
}

func createSignatureBlock(descriptor []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	var h = sha1.New()
	h.Write(descriptor)

	var signature, err = privateKey.Sign(rand.Reader, h.Sum(nil), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign descriptor: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "SIGNATURE", Bytes: signature}), nil
}
