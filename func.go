package dsl

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"math"
	"strconv"
	"strings"

	"github.com/projectdiscovery/govaluate"
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

	key, ok := d.cacheKey(args...)
	if !ok {
		return d.ExpressionFunction(args...)
	}
	if result, err := resultCache.Get(key); err == nil {
		return result, nil
	}

	result, err := d.ExpressionFunction(args...)
	if err == nil {
		_ = resultCache.Set(key, result)
	}

	return result, err
}

// cacheKey encodes the call injectively (a type tag per argument, a length
// prefix per variable-size value) so distinct calls cannot share a key, as
// "f(\"a\", \"b\")" and "f(\"a,b\")" did with a plain separator. ok is false for
// argument types with no unambiguous encoding; those calls bypass the cache.
func (d dslFunction) cacheKey(args ...interface{}) (key uint64, ok bool) {
	var h maphash.Hash
	h.SetSeed(cacheKeySeed)
	writeString(&h, d.Name)

	var b [9]byte
	writeFixed := func(tag argTag, v uint64) {
		b[0] = byte(tag)
		binary.LittleEndian.PutUint64(b[1:], v)
		_, _ = h.Write(b[:])
	}

	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			_ = h.WriteByte(byte(tagString))
			writeString(&h, v)
		case []byte:
			_ = h.WriteByte(byte(tagBytes))
			writeBytes(&h, v)
		case bool:
			var u uint64
			if v {
				u = 1
			}
			writeFixed(tagBool, u)
		case int:
			writeFixed(tagInt, uint64(v))
		case int8:
			writeFixed(tagInt8, uint64(v))
		case int16:
			writeFixed(tagInt16, uint64(v))
		case int32:
			writeFixed(tagInt32, uint64(v))
		case int64:
			writeFixed(tagInt64, uint64(v))
		case uint:
			writeFixed(tagUint, uint64(v))
		case uint8:
			writeFixed(tagUint8, uint64(v))
		case uint16:
			writeFixed(tagUint16, uint64(v))
		case uint32:
			writeFixed(tagUint32, uint64(v))
		case uint64:
			writeFixed(tagUint64, v)
		case float32:
			writeFixed(tagFloat32, uint64(math.Float32bits(v)))
		case float64:
			writeFixed(tagFloat64, math.Float64bits(v))
		default:
			return 0, false
		}
	}

	return h.Sum64(), true
}

type argTag byte

const (
	tagString argTag = iota + 1
	tagBytes
	tagBool
	tagInt
	tagInt8
	tagInt16
	tagInt32
	tagInt64
	tagUint
	tagUint8
	tagUint16
	tagUint32
	tagUint64
	tagFloat32
	tagFloat64
)

// cacheKeySeed is fixed per process because keys only live in the in-memory cache.
var cacheKeySeed = maphash.MakeSeed()

func writeString(h *maphash.Hash, s string) {
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.WriteString(s)
}

func writeBytes(h *maphash.Hash, p []byte) {
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(p)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(p)
}
