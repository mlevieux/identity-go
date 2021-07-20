package identity

import (
	"encoding/base64"
	"encoding/json"
)

// Base64JsonEncode returns the base64 representation of the JSON
// object representing v.
func Base64JsonEncode(v interface{}) (string, error) {
	// Note: []byte values are encoded as base64-encoded strings
	//       (see: https://golang.org/pkg/encoding/json/#Marshal)
	jsonToken, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	b64Token := base64.StdEncoding.EncodeToString(jsonToken)
	return b64Token, nil
}

// Base64JsonDecode typically takes a value returned from Base64JsonEncode
// after decoding it.
func Base64JsonDecode(b64 string, v interface{}) error {
	str, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	err = json.Unmarshal(str, v)
	if err != nil {
		return err
	}
	return nil
}
