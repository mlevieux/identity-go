package identity

import (
	"bytes"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/ed25519"
)

type IdentityTargetType string

const (
	IdentityTargetEmail IdentityTargetType = "email"
	IdentityTargetUser IdentityTargetType = "user"
)

type publicIdentity struct {
	TrustchainID []byte `json:"trustchain_id"`
	Target       IdentityTargetType `json:"target"`
	Value        string `json:"value"`
}

type identity struct {
	publicIdentity
	DelegationSignature          []byte `json:"delegation_signature"`
	EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
	EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
	UserSecret                   []byte `json:"user_secret"`
}

type publicProvisionalIdentity struct {
	publicIdentity
	PublicSignatureKey  []byte `json:"public_signature_key"`
	PublicEncryptionKey []byte `json:"public_encryption_key"`
}

type provisionalIdentity struct {
	publicProvisionalIdentity
	PrivateSignatureKey  []byte `json:"private_signature_key"`
	PrivateEncryptionKey []byte `json:"private_encryption_key"`
}

func generateIdentity(config config, userIDString string) (identity, error) {
	var (
		id identity
	)

	generatedAppID := generateAppID(config.AppSecret)
	if !bytes.Equal(generatedAppID, config.AppID) {
		return id, errors.New("app secret and app ID mismatch")
	}

	userID := hashUserID(config.AppID, userIDString)
	userSecret := createUserSecret(userID)

	epubSignKey, eprivSignKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return id, err
	}

	payload := make([]byte, len(epubSignKey) + len(userID))
	copy(payload, epubSignKey)
	copy(payload[len(epubSignKey):], userID)

	delegationSignature := ed25519.Sign(config.AppSecret, payload)
	id = identity{
		publicIdentity: publicIdentity{
			TrustchainID: config.AppID,
			Target:       IdentityTargetUser,
			Value:        base64.StdEncoding.EncodeToString(userID),
		},
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserSecret:                   userSecret,
	}

	return id, nil
}

func generateProvisionalIdentity(config config, email string) (*provisionalIdentity, error) {
	publicSignatureKey, privateSignatureKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	publicEncryptionKey, privateEncryptionKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	provisionalIdentity := provisionalIdentity{
		publicProvisionalIdentity: publicProvisionalIdentity{
			publicIdentity: publicIdentity{
				TrustchainID: config.AppID,
				Target:       "email",
				Value:        email,
			},
			PublicEncryptionKey: publicEncryptionKey,
			PublicSignatureKey:  publicSignatureKey,
		},
		PrivateSignatureKey:  privateSignatureKey,
		PrivateEncryptionKey: privateEncryptionKey,
	}

	return &provisionalIdentity, nil
}
