package sizedpool

import (
	"context"
	"errors"
	"sync"

	"github.com/projectdiscovery/utils/sync/semaphore"
)

// PoolOption represents an option for configuring the [SizedPool].
type PoolOption[T any] func(*SizedPool[T]) error

// WithSize sets the maximum size of the [SizedPool].
func WithSize[T any](size int64) PoolOption[T] {
	return func(sz *SizedPool[T]) error {
		if size <= 0 {
			return errors.New("size must be positive")
		}
		var err error
		sz.sem, err = semaphore.New(size)
		if err != nil {
			return err
		}
		return nil
	}
}

// WithPool sets the underlying [sync.Pool] for the [SizedPool].
func WithPool[T any](p *sync.Pool) PoolOption[T] {
	return func(sz *SizedPool[T]) error {
		sz.pool = p
		return nil
	}
}

// SizedPool is a pool with a maximum size that blocks on Get when the pool is
// exhausted.
type SizedPool[T any] struct {
	sem  *semaphore.Semaphore
	pool *sync.Pool
}

// New creates a new SizedPool with the given options.
func New[T any](options ...PoolOption[T]) (*SizedPool[T], error) {
	sz := &SizedPool[T]{}
	for _, option := range options {
		if err := option(sz); err != nil {
			return nil, err
		}
	}
	return sz, nil
}

// Get retrieves an item from the pool, blocking if necessary until an item is
// available.
func (sz *SizedPool[T]) Get(ctx context.Context) (T, error) {
	if sz.sem != nil {
		if err := sz.sem.Acquire(ctx, 1); err != nil {
			var t T
			return t, err
		}
	}
	return sz.pool.Get().(T), nil
}

// Put returns an item to the pool and releases the semaphore slot.
func (sz *SizedPool[T]) Put(x T) {
	sz.Discard()
	sz.pool.Put(x)
}

// Discard releases the semaphore slot without returning the item to the pool.
//
// Use this when you need to discard an item obtained via [Get] without reusing
// it. This prevents semaphore leaks when items are intentionally not returned
// to the pool.
func (sz *SizedPool[T]) Discard() {
	if sz.sem != nil {
		sz.sem.Release(1)
	}
}

// Vary capacity by x - it's internally enqueued as a normal Acquire/Release operation as other Get/Put
// but tokens are held internally
func (sz *SizedPool[T]) Vary(ctx context.Context, x int64) error {
	return sz.sem.Vary(ctx, x)
}

// Current size of the pool
func (sz *SizedPool[T]) Size() int64 {
	return sz.sem.Size()
}
