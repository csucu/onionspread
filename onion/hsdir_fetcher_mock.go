package onion

import "github.com/csucu/onionspread/descriptor"

type MockHSDirFetcher struct {
	returnResponsibleHSdirsMap map[string][]descriptor.RouterStatusEntry
	returnErr error
}

func (m *MockHSDirFetcher) CalculateResponsibleHSDirs(descriptorID string) ([]descriptor.RouterStatusEntry, error) {
	return m.returnResponsibleHSdirsMap[descriptorID], m.returnErr
}