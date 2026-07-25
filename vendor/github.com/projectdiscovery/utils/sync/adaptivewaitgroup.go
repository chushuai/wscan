package sync

// Extended version of https://github.com/remeh/sizedwaitgroup

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/utils/sync/semaphore"
)

type AdaptiveGroupOption func(*AdaptiveWaitGroup) error

type AdaptiveWaitGroup struct {
	Size    int
	current *atomic.Int64

	sem *semaphore.Semaphore
	wg  sync.WaitGroup
	mu  sync.Mutex // Mutex to protect access to the Size and semaphore
}

// WithSize sets the initial size of the waitgroup ()
func WithSize(size int) AdaptiveGroupOption {
	return func(wg *AdaptiveWaitGroup) error {
		if err := validateSize(size); err != nil {
			return err
		}
		sem, err := semaphore.New(int64(size))
		if err != nil {
			return err
		}
		wg.sem = sem
		wg.Size = size
		return nil
	}
}

func validateSize(size int) error {
	if size < 1 {
		return errors.New("size must be at least 1")
	}
	return nil
}

func New(options ...AdaptiveGroupOption) (*AdaptiveWaitGroup, error) {
	wg := &AdaptiveWaitGroup{}
	for _, option := range options {
		if err := option(wg); err != nil {
			return nil, err
		}
	}

	wg.wg = sync.WaitGroup{}
	wg.current = &atomic.Int64{}
	return wg, nil
}

func (s *AdaptiveWaitGroup) Add() {
	_ = s.AddWithContext(context.Background())
}

func (s *AdaptiveWaitGroup) AddWithContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		s.current.Add(1)

		// Attempt to acquire a semaphore slot, handle error if acquisition fails
		if err := s.sem.Acquire(ctx, 1); err != nil {
			s.current.Add(-1)
			return err
		}
	}

	s.wg.Add(1)
	return nil
}

func (s *AdaptiveWaitGroup) Done() {
	s.current.Add(-1)
	s.sem.Release(1)
	s.wg.Done()
}

func (s *AdaptiveWaitGroup) Wait() {
	s.wg.Wait()
}

func (s *AdaptiveWaitGroup) Resize(ctx context.Context, size int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateSize(size); err != nil {
		return err
	}

	// Resize the semaphore with the provided context and handle any errors
	if err := s.sem.Resize(ctx, int64(size)); err != nil {
		return err
	}
	s.Size = size
	return nil
}

func (s *AdaptiveWaitGroup) Current() int {
	return int(s.current.Load())
}
