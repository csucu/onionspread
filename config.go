package main

import (
	"encoding/json"
	"errors"
	"os"
)

// Config holds the configuration for the application
type Config struct {
	Address             string    `json:"Address"`
	ControlPortPassword string    `json:"ControlPortPassword"`
	Services            []Service `json:"Services"`
	LogFilePath         string    `json:"LogFilePath"`
}

// Service represents a hidden service that will be balanced
type Service struct {
	PrivateKeyPath   string   `json:"PrivateKeyPath"`
	BackendAddresses []string `json:"BackendAddresses"`
}

// isValid verifies the values in the config
func (c *Config) isValid() error {
	if c.Address == "" {
		return errors.New("missing address")
	}

	for _, onion := range c.Services {
		if onion.PrivateKeyPath == "" {
			return errors.New("missing private key path")
		}

		if len(onion.BackendAddresses) > 60 {
			return errors.New("only a maximum of 60 backend instances is allowed")
		}
	}

	return nil
}

// loadConfig returns a config object given the config file
func loadConfig(filename *string) (*Config, error) {
	var config Config
	configFile, err := os.Open(*filename)
	defer configFile.Close()
	if err != nil {
		return nil, err
	}

	var jsonParser = json.NewDecoder(configFile)
	jsonParser.Decode(&config)

	err = config.isValid()
	if err != nil {
		return nil, err
	}

	return &config, nil
}
