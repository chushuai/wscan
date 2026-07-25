package dsl

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math"
	"strconv"
	"strings"

	"github.com/Knetic/govaluate"
)

type dslFunction struct {
	IsCacheable bool
	Name        string
	// if numberOfArgs is defined the signature is automatically generated
	NumberOfArgs       int
	Signatures         []string
	ExpressionFunction govaluate.ExpressionFunction
}

func (d dslFunction) GetSignatures() []string {
	// fixed number of args implies a static signature
	if d.NumberOfArgs > 0 {
		args := make([]string, 0, d.NumberOfArgs)
		for i := 1; i <= d.NumberOfArgs; i++ {
			args = append(args, "arg"+strconv.Itoa(i))
		}
		argsPart := fmt.Sprintf("(%s interface{}) interface{}", strings.Join(args, ", "))
		signature := d.Name + argsPart
		return []string{signature}
	}

	// multi signatures
	var signatures []string
	for _, signature := range d.Signatures {
		signatures = append(signatures, d.Name+signature)
	}

	return signatures
}

func (d dslFunction) Exec(args ...interface{}) (interface{}, error) {
	// fixed number of args implies the possibility to perform matching between the expected number of args and the ones provided
	if d.NumberOfArgs > 0 {
		if len(args) != d.NumberOfArgs {
			signatures := d.GetSignatures()
			if len(signatures) > 0 {
				return nil, fmt.Errorf("%w. correct method signature %q", ErrInvalidDslFunction, signatures[0])
			}
			return nil, ErrInvalidDslFunction
		}
	}

	if !d.IsCacheable {
		return d.ExpressionFunction(args...)
	}

	functionHash := d.hash(args...)
	if result, err := resultCache.Get(functionHash); err == nil {
		return result, nil
	}

	result, err := d.ExpressionFunction(args...)
	if err == nil {
		_ = resultCache.Set(functionHash, result)
	}

	return result, err
}

func (d dslFunction) hash(args ...interface{}) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(d.Name))
	_, _ = hasher.Write([]byte{'-'})

	// NOTE(dwisiswant0): Using a single byte slice for binary conversions of
	// numeric types avoids repeated mallocs within the loop, improving perf.
	var b [8]byte

	for i, arg := range args {
		switch v := arg.(type) {
		case string:
			_, _ = hasher.Write([]byte(v))
		case []byte:
			_, _ = hasher.Write(v)
		// Booleans
		case bool:
			if v {
				_, _ = hasher.Write([]byte{1})
			} else {
				_, _ = hasher.Write([]byte{0})
			}

		// Integers
		// NOTE(dwisiswant0): TIL! By writing the raw binary representation of
		// numeric types directly to the hasher, we avoid the significant perf
		// and memory overhead of converting em to strings (ex. via `fmt.Sprintf`
		// or `strconv`). This is MUCH faster & reduces GC pressure.
		// We use `binary.LittleEndian` to ensure the byte order is consistent
		// across all machine archs, which is critical for generating
		// deterministic hashes.
		// Proof: `go test -benchmem -run=^$ -bench ^BenchmarkDSLFunctionHash$ .`
		case int:
			binary.LittleEndian.PutUint64(b[:], uint64(v))
			_, _ = hasher.Write(b[:])
		case int8:
			_, _ = hasher.Write([]byte{byte(v)})
		case int16:
			binary.LittleEndian.PutUint16(b[:2], uint16(v))
			_, _ = hasher.Write(b[:2])
		case int32:
			binary.LittleEndian.PutUint32(b[:4], uint32(v))
			_, _ = hasher.Write(b[:4])
		case int64:
			binary.LittleEndian.PutUint64(b[:], uint64(v))
			_, _ = hasher.Write(b[:])
		// Unsigned Integers
		case uint:
			binary.LittleEndian.PutUint64(b[:], uint64(v))
			_, _ = hasher.Write(b[:])
		case uint8: // same as byte
			_, _ = hasher.Write([]byte{v})
		case uint16:
			binary.LittleEndian.PutUint16(b[:2], v)
			_, _ = hasher.Write(b[:2])
		case uint32: // same as rune
			binary.LittleEndian.PutUint32(b[:4], v)
			_, _ = hasher.Write(b[:4])
		case uint64:
			binary.LittleEndian.PutUint64(b[:], v)
			_, _ = hasher.Write(b[:])
		// Floats
		case float32:
			binary.LittleEndian.PutUint32(b[:4], math.Float32bits(v))
			_, _ = hasher.Write(b[:4])
		case float64:
			binary.LittleEndian.PutUint64(b[:], math.Float64bits(v))
			_, _ = hasher.Write(b[:])
		default:
			_, _ = fmt.Fprintf(hasher, "%v", v)
		}

		if i < len(args)-1 {
			_, _ = hasher.Write([]byte{','})
		}
	}

	return strconv.FormatUint(hasher.Sum64(), 10)
}
