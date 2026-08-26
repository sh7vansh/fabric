package protocol

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrMaxStreamsExceeded is returned when the concurrency quota is exceeded.
	ErrMaxStreamsExceeded = errors.New("circuit breaker: max concurrent streams quota exceeded")
)

const (
	// DefaultBufferSize is the standard 32KB buffer size used by StreamManager.
	DefaultBufferSize = 32 * 1024
)

// StreamStats captures cumulative and point-in-time telemetry from the StreamManager.
type StreamStats struct {
	ActiveStreams int64         `json:"active_streams"`
	TotalBridged  int64         `json:"total_bridged"`
	BytesFromAToB int64         `json:"bytes_from_a_to_b"`
	BytesFromBToA int64         `json:"bytes_from_b_to_a"`
	TotalBytes    int64         `json:"total_bytes"`
}

// StreamTelemetry contains performance and transfer metrics for a single bridged stream session.
type StreamTelemetry struct {
	BytesFromAToB int64         `json:"bytes_from_a_to_b"`
	BytesFromBToA int64         `json:"bytes_from_b_to_a"`
	TotalBytes    int64         `json:"total_bytes"`
	Duration      time.Duration `json:"duration"`
	StartTime     time.Time     `json:"start_time"`
	EndTime       time.Time     `json:"end_time"`
	ErrA          error         `json:"err_a,omitempty"`
	ErrB          error         `json:"err_b,omitempty"`
}

// StreamManagerConfig configures the behavior and circuit breakers of StreamManager.
type StreamManagerConfig struct {
	IdleDeadline     time.Duration
	MaxActiveStreams int64
	BufferSize       int
}

// StreamManager provides flow-controlled, buffer-pooled connection bridging with
// idle deadlines, concurrency quotas, half-close propagation, and transfer telemetry.
type StreamManager struct {
	cfg           StreamManagerConfig
	bufferPool    sync.Pool
	activeStreams atomic.Int64
	totalBridged  atomic.Int64
	bytesAToB     atomic.Int64
	bytesBToA     atomic.Int64
}

// NewStreamManager instantiates a StreamManager with the specified configuration.
func NewStreamManager(cfg StreamManagerConfig) *StreamManager {
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	cfg.BufferSize = bufSize

	sm := &StreamManager{
		cfg: cfg,
	}

	sm.bufferPool.New = func() interface{} {
		buf := make([]byte, sm.cfg.BufferSize)
		return &buf
	}

	return sm
}

func (sm *StreamManager) getBuffer() []byte {
	p := sm.bufferPool.Get().(*[]byte)
	return *p
}

func (sm *StreamManager) putBuffer(b []byte) {
	if cap(b) >= sm.cfg.BufferSize {
		b = b[:sm.cfg.BufferSize]
		sm.bufferPool.Put(&b)
	}
}

// Stats returns a snapshot of global stream metrics.
func (sm *StreamManager) Stats() StreamStats {
	aToB := sm.bytesAToB.Load()
	bToA := sm.bytesBToA.Load()
	return StreamStats{
		ActiveStreams: sm.activeStreams.Load(),
		TotalBridged:  sm.totalBridged.Load(),
		BytesFromAToB: aToB,
		BytesFromBToA: bToA,
		TotalBytes:    aToB + bToA,
	}
}

// Bridge establishes bidirectional data transfer between two connections (a and b),
// using pooled 32KB memory buffers, configurable idle deadlines, and half-close propagation.
func (sm *StreamManager) Bridge(a, b net.Conn) (*StreamTelemetry, error) {
	if sm.cfg.MaxActiveStreams > 0 && sm.activeStreams.Load() >= sm.cfg.MaxActiveStreams {
		a.Close()
		b.Close()
		return nil, ErrMaxStreamsExceeded
	}

	sm.activeStreams.Add(1)
	sm.totalBridged.Add(1)
	defer sm.activeStreams.Add(-1)

	telem := &StreamTelemetry{
		StartTime: time.Now(),
	}

	var once sync.Once
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	defer closeBoth()

	var wg sync.WaitGroup
	wg.Add(2)

	var (
		bytesAB, bytesBA int64
		rErrA, wErrB     error
		rErrB, wErrA     error
	)

	// Direction A -> B
	go func() {
		defer wg.Done()
		rErrA, wErrB = sm.transferUni(a, b, &bytesAB, &sm.bytesAToB, &once, closeBoth)
	}()

	// Direction B -> A
	go func() {
		defer wg.Done()
		rErrB, wErrA = sm.transferUni(b, a, &bytesBA, &sm.bytesBToA, &once, closeBoth)
	}()

	wg.Wait()
	telem.BytesFromAToB = bytesAB
	telem.BytesFromBToA = bytesBA
	if rErrA != nil {
		telem.ErrA = rErrA
	} else {
		telem.ErrA = wErrA
	}
	if rErrB != nil {
		telem.ErrB = rErrB
	} else {
		telem.ErrB = wErrB
	}
	telem.EndTime = time.Now()
	telem.Duration = telem.EndTime.Sub(telem.StartTime)
	telem.TotalBytes = telem.BytesFromAToB + telem.BytesFromBToA

	return telem, nil
}

func (sm *StreamManager) transferUni(
	src, dst net.Conn,
	telemBytes *int64,
	smBytes *atomic.Int64,
	once *sync.Once,
	closeBoth func(),
) (rErrOut error, wErrOut error) {
	buf := sm.getBuffer()
	defer sm.putBuffer(buf)

	for {
		if sm.cfg.IdleDeadline > 0 {
			_ = src.SetReadDeadline(time.Now().Add(sm.cfg.IdleDeadline))
			_ = dst.SetWriteDeadline(time.Now().Add(sm.cfg.IdleDeadline))
		}

		n, rErr := src.Read(buf)
		if n > 0 {
			wn, wErr := dst.Write(buf[:n])
			if wn > 0 {
				*telemBytes += int64(wn)
				smBytes.Add(int64(wn))
			}
			if wErr != nil {
				wErrOut = wErr
				break
			}
		}
		if rErr != nil {
			if rErr != io.EOF {
				rErrOut = rErr
			}
			break
		}
	}

	// Propagate half-close read on src if supported
	if cr, ok := src.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}

	// On fatal transfer errors or when dst does not support half-close, tear down both directions.
	// Otherwise on clean EOF, propagate half-close write on dst if supported.
	if rErrOut != nil || wErrOut != nil {
		once.Do(closeBoth)
	} else if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		once.Do(closeBoth)
	}

	return rErrOut, wErrOut
}

// DefaultIdleDeadline is the default idle timeout applied to proxy streams (60s).
const DefaultIdleDeadline = 60 * time.Second

// DefaultStreamManager is the singleton StreamManager used by protocol.Proxy.
var DefaultStreamManager = NewStreamManager(StreamManagerConfig{
	BufferSize:   DefaultBufferSize,
	IdleDeadline: DefaultIdleDeadline,
})

