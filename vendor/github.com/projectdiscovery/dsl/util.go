package dsl

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kataras/jwt"
	"github.com/pkg/errors"
	randint "github.com/projectdiscovery/utils/rand"
)

const (
	numbers = "1234567890"
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	dateFormatRegex        = regexp.MustCompile("%([A-Za-z])")
	defaultDateTimeLayouts = []string{
		time.RFC3339,
		"2006-01-02 15:04:05 Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04 Z07:00",
		"2006-01-02 15:04",
		"2006-01-02 Z07:00",
		"2006-01-02",
	}
)

// toString converts an interface to string in a quick way
func toString(data interface{}) string {
	switch s := data.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case int32:
		return strconv.Itoa(int(s))
	case int16:
		return strconv.FormatInt(int64(s), 10)
	case int8:
		return strconv.FormatInt(int64(s), 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint16:
		return strconv.FormatUint(uint64(s), 10)
	case uint8:
		return strconv.FormatUint(uint64(s), 10)
	case []byte:
		return string(s)
	case fmt.Stringer:
		return s.String()
	case error:
		return s.Error()
	default:
		return fmt.Sprintf("%v", data)
	}
}

func toStringSlice(v interface{}) (m []string) {
	switch vv := v.(type) {
	case []string:
		for _, item := range vv {
			m = append(m, toString(item))
		}
	case []int:
		for _, item := range vv {
			m = append(m, toString(item))
		}
	case []float64:
		for _, item := range vv {
			m = append(m, toString(item))
		}
	}
	return
}

func insertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	buffer.WriteRune(sep)
	return buffer.String()
}

func TrimAll(s, cutset string) string {
	for _, c := range cutset {
		s = strings.ReplaceAll(s, string(c), "")
	}
	return s
}

func RandSeq(base string, n int) string {
	b := make([]rune, n)
	for i := range b {
		rint, _ := randint.IntN(len(base))
		b[i] = rune(base[rint])
	}
	return string(b)
}

func doSimpleTimeFormat(dateTimeFormatFragment [][]string, currentTime time.Time, dateTimeFormat string) (interface{}, error) {
	for _, currentFragment := range dateTimeFormatFragment {
		if len(currentFragment) < 2 {
			continue
		}
		prefixedFormatFragment := currentFragment[0]
		switch currentFragment[1] {
		case "Y", "y":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Year())
		case "M":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, int(currentTime.Month()))
		case "D", "d":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Day())
		case "H", "h":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Hour())
		case "m":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Minute())
		case "S", "s":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Second())
		default:
			return nil, fmt.Errorf("invalid date time format string: %s", prefixedFormatFragment)
		}
	}
	return dateTimeFormat, nil
}

func parseTimeOrNow(arguments []interface{}) (time.Time, error) {
	var currentTime time.Time
	if len(arguments) == 2 {
		switch inputUnixTime := arguments[1].(type) {
		case time.Time:
			currentTime = inputUnixTime
		case string:
			unixTime, err := strconv.ParseInt(inputUnixTime, 10, 64)
			if err != nil {
				return time.Time{}, errors.New("invalid argument type")
			}
			currentTime = time.Unix(unixTime, 0)
		case int64, float64:
			currentTime = time.Unix(int64(inputUnixTime.(float64)), 0)
		default:
			return time.Time{}, errors.New("invalid argument type")
		}
	} else {
		currentTime = time.Now()
	}
	return currentTime, nil
}

func formatDateTime(inputFormat string, matchValue string, timeFragment int) string {
	return strings.ReplaceAll(inputFormat, matchValue, appendSingleDigitZero(strconv.Itoa(timeFragment)))
}

// appendSingleDigitZero appends zero at front if not exists already doing two digit padding
func appendSingleDigitZero(value string) string {
	if len(value) == 1 && (!strings.HasPrefix(value, "0") || value == "0") {
		builder := &strings.Builder{}
		builder.WriteRune('0')
		builder.WriteString(value)
		newVal := builder.String()
		return newVal
	}
	return value
}

func stringNumberToDecimal(args []interface{}, prefix string, base int) (interface{}, error) {
	input := toString(args[0])
	if strings.HasPrefix(input, prefix) {
		base = 0
	}
	if number, err := strconv.ParseInt(input, base, 64); err == nil {
		return float64(number), err
	}
	return nil, fmt.Errorf("invalid number: %s", input)
}

func toChunks(input string, chunkSize int) []string {
	if chunkSize <= 0 || chunkSize >= len(input) {
		return []string{input}
	}
	var chunks = make([]string, 0, (len(input)-1)/chunkSize+1)
	currentLength := 0
	currentStart := 0
	for i := range input {
		if currentLength == chunkSize {
			chunks = append(chunks, input[currentStart:i])
			currentLength = 0
			currentStart = i
		}
		currentLength++
	}
	chunks = append(chunks, input[currentStart:])
	return chunks
}

func pkcs5padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

type algNONE struct {
	algValue string
}

func (a *algNONE) Name() string {
	return a.algValue
}

func (a *algNONE) Sign(key jwt.PrivateKey, headerAndPayload []byte) ([]byte, error) {
	return nil, nil
}

func (a *algNONE) Verify(key jwt.PublicKey, headerAndPayload []byte, signature []byte) error {
	if !bytes.Equal(signature, []byte{}) {
		return jwt.ErrTokenSignature
	}

	return nil
}

func isjwtAlgorithmNone(alg string) bool {
	alg = strings.TrimSpace(alg)
	return strings.ToLower(alg) == "none"
}

func toHexEncodedHash(hashToUse hash.Hash, data string) (interface{}, error) {
	if _, err := hashToUse.Write([]byte(data)); err != nil {
		return nil, err
	}
	return hex.EncodeToString(hashToUse.Sum(nil)), nil
}

func aggregate(values []string) string {
	sort.Strings(values)

	builder := &strings.Builder{}
	for _, value := range values {
		builder.WriteRune('\t')
		builder.WriteString(value)
		builder.WriteRune('\n')
	}
	return builder.String()
}
