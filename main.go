package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/csucu/onionspread/common"
	"github.com/csucu/onionspread/onion"

	"go.uber.org/zap"
	"gopkg.in/alecthomas/kingpin.v2"
)

var debug = kingpin.Flag("debug", "Enable debug mode.").Short('d').Bool()
var configPath = kingpin.Flag("config", "Config path").Short('c').Required().ExistingFile()

func main() {
	kingpin.Version("0.0.1")
	kingpin.Parse()

	// Load config
	var config, err = loadConfig(configPath)
	if err != nil {
		fmt.Printf("failed to load config file: %v", err)
		return
	}

	// Setup logger
	var logger *zap.SugaredLogger
	logger, err = common.NewLogger(*debug, config.LogFilePath)
	if err != nil {
		fmt.Printf("failed to initilize logger: %v", err)
		return
	}

	// Initialising controller
	var controller *onion.Controller
	controller, err = onion.NewController(config.Address, config.ControlPortPassword)
	if err != nil {
		logger.Errorf("failed to initialise controller: %v", err)
		return
	}
	defer controller.Close()

	// Start hsdir fetcher
	var hsdirFetcher = onion.NewHSDirFetcher(controller, logger)
	if err := hsdirFetcher.Start();err != nil {
		logger.Error(err)
		return
	}
	defer hsdirFetcher.Stop()

	// Launch services
	logger.Debug("launching services")
	var wg = &sync.WaitGroup{}
	for _, service := range config.Services {
		wg.Add(1)

		var publicKey, privateKey, err = common.LoadKeysFromFile(service.PrivateKeyPath)
		if err != nil {
			logger.Errorf("failed to load keys from file: %v", err)
			return
		}

		// Start onion
		var masterOnion *onion.Onion
		masterOnion, err = onion.NewOnion(
			controller,
			service.BackendAddresses,
			publicKey,
			privateKey,
			hsdirFetcher,
			logger,
			common.NewTimeProvider(),
			time.Second*3600)
		if err != nil {
			logger.Errorf("failed to initialize onion %v", err)
			return
		}

		go func() {
			defer wg.Done()

			err = masterOnion.Start(time.Minute * 10)
			if err != nil {
				logger.Error(err)
			}

			defer masterOnion.Stop()
		}()
	}

	wg.Wait()
}
