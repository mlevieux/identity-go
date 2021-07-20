package identity

import (
	"errors"
)

func Create(config Config, userID string) (string, error) {
	conf, err := config.fromB64()
	if err != nil {
		return "", err
	}

	id, err := generateIdentity(conf, userID)
	if err != nil {
		return "", err
	}
	return Base64JsonEncode(id)
}

func CreateProvisional(config Config, email string) (string, error) {
	conf, err := config.fromB64()
	if err != nil {
		return "", err
	}

	pid, err := generateProvisionalIdentity(conf, email)
	if err != nil {
		return "", err
	}
	return Base64JsonEncode(pid)
}

func GetPublicIdentity(b64Identity string) (string, error) {
	type anyPublicIdentity struct {
		publicIdentity
		PublicSignatureKey  []byte `json:"public_signature_key,omitempty"`
		PublicEncryptionKey []byte `json:"public_encryption_key,omitempty"`
	}

	var public anyPublicIdentity
	err := Base64JsonDecode(b64Identity, &public)
	if err != nil {
		return "", err
	}

	if public.Target != "user" && public.Target != "email" {
		return "", errors.New("unsupported identity target")
	}

	return Base64JsonEncode(public)
}
