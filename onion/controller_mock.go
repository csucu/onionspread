package onion

import (
	"context"

	"github.com/cretz/bine/control"
	"github.com/csucu/onionspread/descriptor"
)

type MockController struct {
	ReturnedHiddenServiceDescriptor    *descriptor.HiddenServiceDescriptor
	ReturnedRouterStatusEntries        []descriptor.RouterStatusEntry
	ReturnedHiddenServiceDescriptorRaw string
	ReturnedErr                        error
	PostedDescriptors                  map[string]string
	FetchedDescriptors                 map[string]*descriptor.HiddenServiceDescriptor
	PostedDescriptor                   string
}

func (m *MockController) FetchHiddenServiceDescriptor(address, server string, ctx context.Context) (
	*descriptor.HiddenServiceDescriptor, error) {
	if m.ReturnedErr != nil {
		return nil, m.ReturnedErr
	}

	return m.FetchedDescriptors[address], nil
}

func (m *MockController) PostHiddenServiceDescriptor(desc string, servers []string, address string) error {
	if m.ReturnedErr != nil {
		return m.ReturnedErr
	}

	if servers == nil {
		m.PostedDescriptor = desc
		return nil
	}

	if m.PostedDescriptors == nil {
		m.PostedDescriptors = make(map[string]string)
	}

	m.PostedDescriptors[servers[0]] = desc

	return m.ReturnedErr
}

func (m *MockController) FetchRouterStatusEntries() ([]descriptor.RouterStatusEntry, error) {
	return m.ReturnedRouterStatusEntries, m.ReturnedErr
}

func (m *MockController) GetConn() *control.Conn {
	return nil
}