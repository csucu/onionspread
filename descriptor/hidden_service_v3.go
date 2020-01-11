package descriptor

import (
	"strconv"
	"strings"
)

type HiddenServiceDescriptorV3 struct {
	Version         int
	LifeTime        int
	SigningCert     string
	RevisionCounter int
	SuperEncryptedRaw  string
	Signature       string
}

type IntroductionPointV3 struct {
	// link_specifiers
	OnionKeyRaw   string
	AuthKeyCert   string
	EncKeyRaw     string
	EncKeyCert    string
	LegacyKeyRaw  string
	LegacyKeyCert string
}

func ParseHiddenServiceDescriptorV3(descriptorRaw string) (*HiddenServiceDescriptorV3, error) {
	var descriptor = &HiddenServiceDescriptorV3{}
	var lines = strings.Split(descriptorRaw, "\n")
	var err error

	for i, line := range lines {
		var words = strings.Split(line, " ")
		switch words[0] {
		case "hs-descriptor":
			descriptor.Version, err = strconv.Atoi(words[1])
		case "descriptor-lifetime":
			descriptor.LifeTime, err = strconv.Atoi(words[1])
		case "descriptor-signing-key-cert":
			descriptor.SigningCert, err = extractEntry("-----BEGIN ED25519 CERT-----", lines[i:])
		case "revision-counter":
			descriptor.RevisionCounter, err = strconv.Atoi(words[1])
		case "superencrypted":
			descriptor.SuperEncryptedRaw, err = extractEntry("-----END MESSAGE-----", lines[i:])
		case "signature":
			descriptor.Signature = words[1]
		}

		if err != nil {
			return nil, err
		}
	}

	return descriptor, nil
}

//
//func (f *HiddenServiceDescriptorV3) decryptOuterLayer(RevisionCounter) {
//// outer_layer, revision_counter, subcredential, blinded_key
//
//}
//
//// def _decrypt_layer(encrypted_block, constant, revision_counter, subcredential, blinded_key):
//func (f *HiddenServiceDescriptorV3) decryptLayer(layer string, strConst string, /* revision_counter, subcredential, blinded_key */) {
//
//}
