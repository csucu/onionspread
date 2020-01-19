package onion

import (
	"context"
	"fmt"
	"net/textproto"
	"sync"
	"time"

	"github.com/cretz/bine/control"
	"github.com/csucu/onionspread/descriptor"
)

// IController is a interface for Controller
type IController interface {
	FetchHiddenServiceDescriptor(string, string, context.Context) (*descriptor.HiddenServiceDescriptor, error)
	PostHiddenServiceDescriptor(string, []string, string) error
	FetchRouterStatusEntries() ([]descriptor.RouterStatusEntry, error)
	GetConn() *control.Conn
}

// Controller represents a tor controller, it is essentially a wrapper over Bine
type Controller struct {
	conn *control.Conn
	mux  sync.Mutex
}

// FetchHiddenServiceDescriptor returns a hidden service descriptor for the requested address
func (c *Controller) FetchHiddenServiceDescriptor(address, server string, ctx context.Context) (*descriptor.HiddenServiceDescriptor, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	eventCh := make(chan control.Event)
	defer close(eventCh)

	err := c.conn.AddEventListener(eventCh, control.EventCodeHSDescContent)
	if err != nil {
		return nil, err
	}
	defer c.conn.RemoveEventListener(eventCh, control.EventCodeHSDescContent)

	err = c.conn.GetHiddenServiceDescriptorAsync(address, server)
	if err != nil {
		return nil, err
	}

	// Grab events
	eventCtx, eventCancel := context.WithTimeout(ctx, 45*time.Second)
	defer eventCancel()

	errCh := make(chan error, 1)

	go func() { errCh <- c.conn.HandleEvents(eventCtx) }()
	for {
		select {
		case <-eventCtx.Done():
			return nil, err
		case err := <-errCh:
			return nil, err
		case event := <-eventCh:
			var hsEvent = event.(*control.HSDescContentEvent)
			if hsEvent.Descriptor == "" {
				continue
			}

			return descriptor.ParseHiddenServiceDescriptor(hsEvent.Descriptor)
		}
	}
}

// PostHiddenServiceDescriptor posts a hidden service descriptor.
func (c *Controller) PostHiddenServiceDescriptor(desc string, servers []string, address string) error {
	return c.conn.PostHiddenServiceDescriptorAsync(desc, servers, "")
}

// FetchRouterStatusEntries requests the router status info from the controller
func (c *Controller) FetchRouterStatusEntries() ([]descriptor.RouterStatusEntry, error) {
	data, err := c.conn.GetInfo("ns/all")
	if err != nil {
		return nil, fmt.Errorf("error fetching RouterStatusEntries: %v", err)
	}

	return descriptor.ParseRouterStatusEntriesRaw(data[0].Val)
}

// GetConn returns the underlining controller connection
func (c *Controller) GetConn() *control.Conn {
	return c.conn
}

// Close closes the underlining controller connection
func (c *Controller) Close() error {
	return c.conn.Close()
}

// NewController constructs a new controller
func NewController(address, controlPortPassword string) (*Controller, error) {
	textprotoConn, err := textproto.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial error: %v", err)
	}

	// Connect to tor controller
	conn := control.NewConn(textprotoConn)
	if err = conn.Authenticate(controlPortPassword); err != nil {
		return nil, fmt.Errorf("authentication error: %v", err)
	}

	return &Controller{
		conn: conn,
	}, nil
}
