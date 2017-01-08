package utils

import "time"

type Timer struct {
	t          *time.Timer
	C          <-chan time.Time
	expiration time.Time
}

func NewTimer(d time.Duration) *Timer {
	t := time.NewTimer(d)
	return &Timer{
		t:          t,
		C:          t.C,
		expiration: time.Now().Add(d),
	}
}

func (t *Timer) Stop() bool {
	t.expiration = time.Time{}
	return t.t.Stop()
}

func (t *Timer) Reset(d time.Duration) bool {
	t.expiration = time.Now().Add(d)
	return t.t.Reset(d)
}

func (t *Timer) GetDelay() time.Duration {
	if t.expiration.IsZero() {
		return InfDuration
	}
	return t.expiration.Sub(time.Now())
}
