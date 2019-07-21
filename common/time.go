package common

import "time"

type ITimeProvider interface {
	Now() time.Time
}

type TimeProvider struct{}

func (t *TimeProvider) Now() time.Time {
	return time.Now()
}

func NewTimeProvider() ITimeProvider {
	return &TimeProvider{}
}
