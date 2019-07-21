package common

import "time"

type MockTimeProvider struct {
	returnTime time.Time
}

func (m *MockTimeProvider) Now() time.Time {
	return m.returnTime
}

func (m *MockTimeProvider) Set(theTime time.Time) {
	m.returnTime = theTime
}
