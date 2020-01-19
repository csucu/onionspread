package onion

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cretz/bine/control"
	"github.com/csucu/onionspread/descriptor"
	"go.uber.org/zap"
)

// IHSDirFetcher is the interface for HSDirFetcher
type IHSDirFetcher interface {
	CalculateResponsibleHSDirs(string) ([]descriptor.RouterStatusEntry, error)
}

// HSDirFetcher maintains a list of HSDirs which it gets from the consensus, the list is updated every time
// the controller returns an status_general event. It is used to calculate the responsible hsdirs for a given
// service and is safe for concurrent use.
type HSDirFetcher struct {
	controller IController
	logger     *zap.SugaredLogger
	hsDirs     []descriptor.RouterStatusEntry

	hsDirsLock sync.RWMutex

	once sync.Once
	stop chan struct{}
}

// update refreshes the internal list of hsdirs
func (f *HSDirFetcher) update() error {
	routerEntries, err := f.controller.FetchRouterStatusEntries()
	if err != nil {
		return err
	}

	if len(routerEntries) == 0 {
		return errors.New("failed to fetch router status entries")
	}

	var HSDirs []descriptor.RouterStatusEntry
	// grab all hsdirs
	for _, routerStatusEntry := range routerEntries {
		if routerStatusEntry.Flags.HSDir {
			HSDirs = append(HSDirs, routerStatusEntry)
		}
	}

	f.hsDirsLock.Lock()
	f.hsDirs = HSDirs
	f.hsDirsLock.Unlock()

	return nil
}

// CalculateResponsibleHSDirs returns the responsible hsdirs given a descriptor ID
func (f *HSDirFetcher) CalculateResponsibleHSDirs(descriptorID string) ([]descriptor.RouterStatusEntry, error) {
	decoded, err := base32.StdEncoding.DecodeString(descriptorID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode descriptor id: %v", err)
	}

	descHex := strings.ToUpper(strings.TrimSpace(hex.EncodeToString(decoded)))

	var responsibleHSDirs []descriptor.RouterStatusEntry
	var nAdded int

	f.hsDirsLock.RLock()
	defer f.hsDirsLock.RUnlock()

	HSDirsSize := len(f.hsDirs)
	startIndex := sort.Search(HSDirsSize, func(i int) bool { return f.hsDirs[i].Fingerprint >= descHex })
	if startIndex == HSDirsSize {
		startIndex = 0
	}

	currentIndex := startIndex
	for nAdded < numberOfConsecutiveReplicas {
		// add a check to see if we've already added
		responsibleHSDirs = append(responsibleHSDirs, f.hsDirs[currentIndex])
		nAdded += 1
		currentIndex += 1
		// loop back around to the start of the ring
		if currentIndex >= HSDirsSize {
			currentIndex = 0
		}

		if currentIndex == startIndex {
			break
		}
	}

	return responsibleHSDirs, nil
}

// Start starts the HSDirFetcher
func (f *HSDirFetcher) Start() error {
	f.logger.Debug("hsdir_fetcher: starting")

	err := f.update()
	if err != nil {
		return err
	}

	go func() {
		err = f.listen()
		if err != nil {
			f.logger.Info("hsdir_fetcher: failed to start: %v", err)
		}
	}()

	return nil
}

// Stop stops the HSDirFetcher
func (f *HSDirFetcher) Stop() {
	f.once.Do(func() {
		close(f.stop)
		f.logger.Debug("hsdir_fetcher: stopping")
	})
}

// listen listens for status general events from the tor controller
// when it receives the event it updates its internal hsdir list
func (f *HSDirFetcher) listen() error {
	eventCh := make(chan control.Event)
	defer close(eventCh)

	err := f.controller.GetConn().AddEventListener(eventCh, control.EventCodeStatusGeneral)
	if err != nil {
		return err
	}
	defer f.controller.GetConn().RemoveEventListener(eventCh, control.EventCodeStatusGeneral)

	// Grab events
	eventCtx := context.Background()
	defer eventCtx.Done()

	errCh := make(chan error, 1)

	go func() { errCh <- f.controller.GetConn().HandleEvents(eventCtx) }()
	for {
		select {
		case <-f.stop:
			return nil
		case <-eventCtx.Done():
			f.logger.Info("hsdir_fetcher: event context closed, stopping listener")
			return nil
		case err := <-errCh:
			f.logger.Errorf("hsdir_fetcher: error channel: %v", err)
			return err
			//return nil, err
		case event := <-eventCh:
			f.logger.Debug("hsdir_fetcher: got a new event")
			statusEvent := event.(*control.StatusEvent)
			if statusEvent.Code() == control.EventCodeStatusGeneral {
				f.logger.Debug("hsdir_fetcher: event is a status general event, updating")
				err = f.update()
				if err != nil {
					f.logger.Errorf("hsdir_fetcher: failed to update: %v", err)
				}
			}
		}
	}
}

// NewHSDirFetcher returns a new HSDirFetcher
func NewHSDirFetcher(controller IController, logger *zap.SugaredLogger) *HSDirFetcher {
	return &HSDirFetcher{
		controller: controller,
		logger:     logger,
	}
}
