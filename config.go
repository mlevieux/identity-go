package identity

import (
	"encoding/base64"
	"fmt"
)

type Config struct {
	AppID     string
	AppSecret string
}

type config struct {
	AppID     []byte
	AppSecret []byte
}

func (cfg Config) fromB64() (config, error) {
	var (
		c   config
		err error
	)

	c.AppID, err = base64.StdEncoding.DecodeString(cfg.AppID)
	if err != nil {
		return c, fmt.Errorf("unable to decode AppID '%s', should be a valid base64 string", cfg.AppID)
	}
	if len(c.AppID) != AppPublicKeySize {
		return c, fmt.Errorf("wrong size for AppID: %d, should be %d", AppPublicKeySize, len(c.AppID))
	}

	c.AppSecret, err = base64.StdEncoding.DecodeString(cfg.AppSecret)
	if err != nil {
		return c, fmt.Errorf("unable to decode AppSecret '%s', should be a valid base64 string", cfg.AppSecret)
	}
	if len(c.AppSecret) != AppSecretSize {
		return c, fmt.Errorf("wrong size for AppSecret: %d, should be %d", AppSecretSize, len(c.AppSecret))
	}

	return c, err
}
