package onion

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/csucu/onionspread/common"
	"github.com/csucu/onionspread/descriptor"
	"go.uber.org/zap"
)

const (
	replicaSetSize              = 2
	numberOfConsecutiveReplicas = 3
	maxIntroPoints              = 10
	descriptorOverlapPeriod     = 3600
)

// Onion represents a hidden service that will balance a number of backend services
type Onion struct {
	controller      IController
	hsDirFetcher    IHSDirFetcher
	address         string
	backendOnions   backendOnions
	permanentID     []byte
	publicKey       *rsa.PublicKey
	privateKey      *rsa.PrivateKey
	publishInterval time.Duration
	lastPublishTime int64
	logger          *zap.SugaredLogger
	time            common.ITimeProvider

	once sync.Once
	stop chan struct{}
}

// backendOnions represents a backend hidden service that will be used for balancing
type backendOnions struct {
	addresses                       []string
	descriptors                     []descriptor.HiddenServiceDescriptor
	totalNumberOfIntroductionPoints int
	newDescriptorsAvailable         bool
}

// Start starts the onion service ticker
func (o *Onion) Start(interval time.Duration) error {
	o.logger.Infof("Onion %s: starting service", o.address)
	var ctx = context.Background()

	var ticker = time.NewTicker(interval) // change publish interval to intro fetch interval
	for {
		ctx, _ = context.WithTimeout(ctx, time.Second*45)
		var introPointsChanged, err = o.introductionPointsChanged(ctx)
		if err != nil {
			o.logger.Errorf("Onion %s: failed to check if introduction points have changed: %v", o.address, err)
			// continue or just carry on?
		}

		if introPointsChanged || o.descriptorIDChangingSoon() || o.notPublishedDescriptorRecently() {
			err = o.balance(ctx) // catch error and log? wait a little while and repeat
			if err != nil {
				o.logger.Errorf("Onion %s: failed to balance: %v", o.address, err)
			}
		}

		select {
		case <-o.stop:
			return nil
		case <-ticker.C:
			continue
		}
	}
}

// Stop stops the onion service ticker
func (o *Onion) Stop() {
	o.once.Do(func() {
		close(o.stop)
		o.logger.Infof("Onion %s: stopping service", o.address)
	})
}

func (o *Onion) balance(ctx context.Context) error {
	o.logger.Debugf("Onion %s: balancing", o.address)

	var err error
	if !o.backendOnions.newDescriptorsAvailable {
		o.logger.Debugf("Onion %s: no new descriptors available", o.address)
		o.backendOnions.descriptors, o.backendOnions.totalNumberOfIntroductionPoints, err = o.fetchBackendDescriptors(ctx)
		if err != nil {
			// log something?
			return err
		}
	}

	o.backendOnions.newDescriptorsAvailable = false

	// generate descriptors and publish them
	switch {
	case o.backendOnions.totalNumberOfIntroductionPoints > maxIntroPoints:
		// publish same descriptor to all responsible hsdirs
		err = o.multiDescriptorGenerateAndPublish(o.backendOnions.descriptors)
	default:
		// publish different descriptors to each of the responsible hsdirs
		err = o.singleDescriptorGenerateAndPublish(o.backendOnions.descriptors)
	}
	if err != nil {
		o.logger.Errorf("Onion %s: %v", o.address, err)
	}

	o.lastPublishTime = o.time.Now().Unix()

	o.logger.Infof("Onion %s: published descriptors successfully", o.address)
	return nil
}

func (o *Onion) fetchBackendDescriptors(ctx context.Context) ([]descriptor.HiddenServiceDescriptor, int, error) {
	o.logger.Debugf("Onion %s: fetching backend descriptors", o.address)
	select {
	case <-ctx.Done():
		return nil, 0, fmt.Errorf("failed to fetch backend descriptors: %v", ctx.Err())
	default:
	}

	var backendDescriptors []descriptor.HiddenServiceDescriptor
	var totalNumOfIntroPoints = 0

	for _, address := range o.backendOnions.addresses {
		var desc, err = o.controller.FetchHiddenServiceDescriptor(address, "", ctx)
		if err != nil {
			o.logger.Errorf("Onion %s: failed to fetch descriptor: %v", o.address, err)
			continue
		}

		if desc == nil {
			o.logger.Error("Onion %s: fetch returned empty descriptor", o.address)
			continue
		}

		backendDescriptors = append(backendDescriptors, *desc)
		totalNumOfIntroPoints += len(desc.IntroductionPoints)
	}

	if totalNumOfIntroPoints == 0 {
		o.logger.Errorf("Onion %s: failed to fetch any descriptors", o.address)
		return nil, 0, errors.New("failed to fetch any descriptors")
	}

	return backendDescriptors, totalNumOfIntroPoints, nil
}

// singleDescriptorGenerateAndPublish uses the same set of introduction points for all the responsible hsdirs
func (o *Onion) singleDescriptorGenerateAndPublish(backendDescriptors []descriptor.HiddenServiceDescriptor) error {
	o.logger.Debugf("Onion %s: publishing a single descriptor to all hsdirs", o.address)
	var introductionPoints []descriptor.IntroductionPoint
	for _, desc := range backendDescriptors {
		introductionPoints = append(introductionPoints, desc.IntroductionPoints...)
	}

	var now = o.time.Now()
	var i byte
	for i = 0; i < replicaSetSize; i++ {
		var balancedDescriptor, err = descriptor.GenerateDescriptorRaw(introductionPoints, now, i, 0,
			"", o.publicKey, o.privateKey, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to generate descriptor: %v", err)
		}

		err = o.controller.PostHiddenServiceDescriptor(string(balancedDescriptor), nil, "")
		if err != nil {
			return fmt.Errorf("failed to post descriptor: %v", err)
		}
	}

	return nil
}

// multiDescriptorGenerateAndPublish iterates the introduction points for each responsible hsdirs
func (o *Onion) multiDescriptorGenerateAndPublish(backendDescriptors []descriptor.HiddenServiceDescriptor) error {
	o.logger.Debugf("Onion %s: publishing multiple descriptors to all hsdirs", o.address)
	var introductionPoints [][]descriptor.IntroductionPoint
	for _, desc := range backendDescriptors {
		introductionPoints = append(introductionPoints, desc.IntroductionPoints)
	}
	var introductionPointItr = descriptor.NewIntroductionPointsIterator(introductionPoints)

	// Calculate responsible hs dirs per replica then generate a new deecriptor then publish
	var now = o.time.Now()
	var i byte
	for i = 0; i < replicaSetSize; i++ {
		var descID, err = common.CalculateDescriptorID(o.permanentID, now.Unix(), i, 0, "")
		if err != nil {
			return fmt.Errorf("failed to calculate descriptor ID: %v", err)
		}

		var responsibleHSDirs []descriptor.RouterStatusEntry
		responsibleHSDirs, err = o.hsDirFetcher.CalculateResponsibleHSDirs(string(descID))
		if err != nil {
			return fmt.Errorf("failed to calculate responsible HSDirs: %v", err)
		}

		// Publish a different descriptor to each responsible directory
		for _, hsDir := range responsibleHSDirs {
			var balancedDescriptor, err = descriptor.GenerateDescriptorRaw(introductionPointItr.Next(), now, i,
				0, "", o.publicKey, o.privateKey, o.permanentID, descID)
			if err != nil {
				return fmt.Errorf("failed to generate descriptor: %v", err)
			}

			err = o.controller.PostHiddenServiceDescriptor(string(balancedDescriptor), []string{hsDir.Fingerprint}, "")
			if err != nil {
				o.logger.Errorf("Onion %s: failed to post descriptor: %v", o.address, err)
			}
		}
	}

	//  todo: maybe add a check to see if we have failed to post any descriptors to any of the hsdirs and return err?

	return nil
}

func (o *Onion) descriptorIDChangingSoon() bool {
	var secondsValid = common.DescriptorIDValidUntil(o.permanentID, o.time.Now().Unix())

	if secondsValid < descriptorOverlapPeriod {
		o.logger.Debugf("Onion %s: descriptor ID changing soon", o.address)
		return true
	}

	return false
}

func (o *Onion) notPublishedDescriptorRecently() bool {
	if o.lastPublishTime == 0 {
		return true
	}

	if o.time.Now().Unix()-o.lastPublishTime > int64(o.publishInterval) {
		o.logger.Debugf("Onion %s: not published any descriptor in awhile", o.address)
		return true
	}

	return false
}

func (o *Onion) introductionPointsChanged(ctx context.Context) (bool, error) {
	var backendDescriptors, totalNumOfintoPoints, err = o.fetchBackendDescriptors(ctx)
	if err != nil {
		return false, err
	}

	if len(o.backendOnions.descriptors) == 0 {
		o.logger.Debugf("Onion %s: no descriptors stored previously, so storing new backend descriptors", o.address)
		o.backendOnions.descriptors = backendDescriptors
		o.backendOnions.newDescriptorsAvailable = true
		o.backendOnions.totalNumberOfIntroductionPoints = totalNumOfintoPoints
		return true, nil
	}

	for i, descriptor := range backendDescriptors {
		if o.backendOnions.descriptors[i].IntroductionPointsRaw != descriptor.IntroductionPointsRaw {
			o.logger.Debugf("Onion %s: introduction points have changed, so storing new backend descriptors", o.address)
			o.backendOnions.descriptors = backendDescriptors
			o.backendOnions.newDescriptorsAvailable = true
			o.backendOnions.totalNumberOfIntroductionPoints = totalNumOfintoPoints
			return true, nil
		}
	}

	return false, nil
}

// NewOnion constructs a new master hidden service that will balance a set of backend services
func NewOnion(controller IController, backendAddresses []string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, fetcher IHSDirFetcher, logger *zap.SugaredLogger, time common.ITimeProvider, publishInterval time.Duration) (*Onion, error) {
	var permanentID, err = common.CalculatePermanentID(*publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate permanent ID: %v", err)
	}

	return &Onion{
		controller: controller,
		address:    common.CalculateOnionAddress(permanentID),
		backendOnions: backendOnions{
			addresses: backendAddresses,
		},
		publicKey:       publicKey,
		privateKey:      privateKey,
		permanentID:     permanentID,
		publishInterval: publishInterval,
		stop:            make(chan struct{}),
		hsDirFetcher:    fetcher,
		logger:          logger,
		time:            time,
	}, nil
}
