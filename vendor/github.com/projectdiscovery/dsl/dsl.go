package dsl

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/Mzack9999/gcache"
	"github.com/asaskevich/govalidator"
	"github.com/brianvoe/gofakeit/v7"
	"github.com/gosimple/slug"
	"github.com/hashicorp/go-version"
	"github.com/iangcarroll/cookiemonster/pkg/monster"
	"github.com/kataras/jwt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/dsl/deserialization"
	"github.com/projectdiscovery/dsl/llm"
	"github.com/projectdiscovery/dsl/randomip"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gostruct"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/utils/conn/connpool"
	jarm "github.com/projectdiscovery/utils/crypto/jarm"
	"github.com/projectdiscovery/utils/errkit"
	hexutil "github.com/projectdiscovery/utils/hex"
	"github.com/projectdiscovery/utils/html"
	maputils "github.com/projectdiscovery/utils/maps"
	randint "github.com/projectdiscovery/utils/rand"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/sashabaranov/go-openai"
	"github.com/spaolacci/murmur3"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	// FunctionNames is a list of function names for expression evaluation usages
	FunctionNames []string

	// DefaultHelperFunctions is a pre-compiled list of govaluate DSL functions
	DefaultHelperFunctions map[string]govaluate.ExpressionFunction

	funcSignatureRegex = regexp.MustCompile(`(\w+)\s*\((?:([\w\d,\s]+)\s+([.\w\d{}&*]+))?\)([\s.\w\d{}&*]+)?`)

	// ErrParsingArg is error when parsing value of argument
	// Use With Caution: Nuclei ignores this error in extractors(ref: https://github.com/projectdiscovery/nuclei/issues/3950)
	ErrParsingArg = errkit.New("error parsing argument value")

	errDuplicateFunc = errors.New("duplicate function")

	DefaultMaxDecompressionSize = int64(10 * 1024 * 1024) // 10MB
	DefaultCacheSize            = 6144
	resultCache                 = gcache.New[string, interface{}](DefaultCacheSize).Build()

	// Initialize faker functions
	faker = gofakeit.New(0)
)

// firstNonEmptyEnv returns the first non-empty environment variable value
// from the provided list of keys (checked in order).
func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

var PrintDebugCallback func(args ...interface{}) error

var functions []dslFunction
var fakerFunctions []dslFunction

func AddFunction(function dslFunction) error {
	for _, f := range functions {
		if function.Name == f.Name {
			return errkit.Wrapf(errDuplicateFunc, "duplicate helper function key: %q", f.Name)
		}
	}
	functions = append(functions, function)
	return nil
}

func addFakerFunction(function dslFunction) error {
	for _, f := range functions {
		if function.Name == f.Name {
			return fmt.Errorf("%w: %q", errDuplicateFunc, f.Name)
		}
	}
	fakerFunctions = append(fakerFunctions, function)
	return nil
}

func MustAddFunction(function dslFunction) {
	if err := AddFunction(function); err != nil {
		panic(err)
	}
}

func init() {
	// note: index helper is zero based
	MustAddFunction(NewWithPositionalArgs("index", 2, true, func(args ...interface{}) (interface{}, error) {
		index, err := strconv.ParseInt(toString(args[1]), 10, 64)
		if err != nil {
			return nil, err
		}
		// If the first argument is a slice, we index into it
		switch v := args[0].(type) {
		case []string:
			l := int64(len(v))
			if index < 0 || index >= l {
				return nil, fmt.Errorf("index out of range for %v: %d", v, index)
			}
			return v[index], nil
		default:
			// Otherwise, we index into the string
			str := toString(v)
			l := int64(len(str))
			if index < 0 || index >= l {
				return nil, fmt.Errorf("index out of range for %v: %d", v, index)
			}
			return string(str[index]), nil
		}
	}))

	MustAddFunction(NewWithPositionalArgs("len", 1, true, func(args ...interface{}) (interface{}, error) {
		var length int
		value := reflect.ValueOf(args[0])
		switch value.Kind() {
		case reflect.Slice:
			length = value.Len()
		case reflect.Map:
			length = value.Len()
		default:
			length = len(toString(args[0]))
		}
		return float64(length), nil
	}))

	MustAddFunction(NewWithPositionalArgs("to_upper", 1, true, func(args ...interface{}) (interface{}, error) {
		return strings.ToUpper(toString(args[0])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("to_lower", 1, true, func(args ...interface{}) (interface{}, error) {
		return strings.ToLower(toString(args[0])), nil
	}))
	MustAddFunction(NewWithMultipleSignatures("sort", []string{
		"(input string) string",
		"(input number) string",
		"(elements ...interface{}) []interface{}"},
		true,
		func(args ...interface{}) (interface{}, error) {
			argCount := len(args)
			switch argCount {
			case 0:
				return nil, ErrInvalidDslFunction
			case 1:
				runes := []rune(toString(args[0]))
				sort.Slice(runes, func(i int, j int) bool {
					return runes[i] < runes[j]
				})
				return string(runes), nil
			default:
				tokens := make([]string, 0, argCount)
				for _, arg := range args {
					tokens = append(tokens, toString(arg))
				}
				sort.Strings(tokens)
				return tokens, nil
			}
		},
	))

	MustAddFunction(NewWithMultipleSignatures("zip", []string{"(file_entry string, content string, ... ) []byte"}, true, func(args ...interface{}) (interface{}, error) {
		if len(args) == 0 || len(args)%2 != 0 {
			return nil, fmt.Errorf("zip function requires pairs of file entry and content")
		}

		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)

		for i := 0; i < len(args); i += 2 {
			fileEntry, ok := args[i].(string)
			if !ok {
				return nil, fmt.Errorf("file entry must be a string")
			}
			content, ok := args[i+1].(string)
			if !ok {
				return nil, fmt.Errorf("content must be a string")
			}

			f, err := zipWriter.Create(fileEntry)
			if err != nil {
				return nil, err
			}
			_, err = f.Write([]byte(content))
			if err != nil {
				return nil, err
			}
		}

		err := zipWriter.Close()
		if err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}))
	MustAddFunction(NewWithMultipleSignatures("uniq", []string{
		"(input string) string",
		"(input number) string",
		"(elements ...interface{}) []interface{}"},
		true,
		func(args ...interface{}) (interface{}, error) {
			argCount := len(args)
			switch argCount {
			case 0:
				return nil, ErrInvalidDslFunction
			case 1:
				builder := &strings.Builder{}
				visited := make(map[rune]struct{})
				for _, i := range toString(args[0]) {
					if _, isRuneSeen := visited[i]; !isRuneSeen {
						builder.WriteRune(i)
						visited[i] = struct{}{}
					}
				}
				return builder.String(), nil
			default:
				result := make([]string, 0, argCount)
				visited := make(map[string]struct{})
				for _, i := range args[0:] {
					if _, isStringSeen := visited[toString(i)]; !isStringSeen {
						result = append(result, toString(i))
						visited[toString(i)] = struct{}{}
					}
				}
				return result, nil
			}
		},
	))
	MustAddFunction(NewWithPositionalArgs("repeat", 2, true, func(args ...interface{}) (interface{}, error) {
		count, err := strconv.Atoi(toString(args[1]))
		if err != nil {
			return nil, ErrInvalidDslFunction
		}
		return strings.Repeat(toString(args[0]), count), nil
	}))
	MustAddFunction(NewWithPositionalArgs("replace", 3, true, func(args ...interface{}) (interface{}, error) {
		return strings.ReplaceAll(toString(args[0]), toString(args[1]), toString(args[2])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("replace_regex", 3, true, func(args ...interface{}) (interface{}, error) {
		compiled, err := regexp.Compile(toString(args[1]))
		if err != nil {
			return nil, err
		}
		return compiled.ReplaceAllString(toString(args[0]), toString(args[2])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("trim", 2, true, func(args ...interface{}) (interface{}, error) {
		return strings.Trim(toString(args[0]), toString(args[1])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("trim_left", 2, true, func(args ...interface{}) (interface{}, error) {
		return strings.TrimLeft(toString(args[0]), toString(args[1])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("trim_right", 2, true, func(args ...interface{}) (interface{}, error) {
		return strings.TrimRight(toString(args[0]), toString(args[1])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("trim_space", 1, true, func(args ...interface{}) (interface{}, error) {
		return strings.TrimSpace(toString(args[0])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("trim_prefix", 2, true, func(args ...interface{}) (interface{}, error) {
		return strings.TrimPrefix(toString(args[0]), toString(args[1])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("trim_suffix", 2, true, func(args ...interface{}) (interface{}, error) {
		return strings.TrimSuffix(toString(args[0]), toString(args[1])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("reverse", 1, true, func(args ...interface{}) (interface{}, error) {
		return stringsutil.Reverse(toString(args[0])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("base64", 1, true, func(args ...interface{}) (interface{}, error) {
		return base64.StdEncoding.EncodeToString([]byte(toString(args[0]))), nil
	}))
	MustAddFunction(NewWithPositionalArgs("gzip", 1, true, func(args ...interface{}) (interface{}, error) {
		buffer := &bytes.Buffer{}
		writer := gzip.NewWriter(buffer)
		if _, err := writer.Write([]byte(args[0].(string))); err != nil {
			_ = writer.Close()
			return "", err
		}
		_ = writer.Close()

		return buffer.String(), nil
	}))
	MustAddFunction(NewWithSingleSignature("gzip_decode",
		"(data string, optionalReadLimit int) string",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) == 0 {
				return nil, ErrInvalidDslFunction
			}

			argData := toString(args[0])
			readLimit := DefaultMaxDecompressionSize

			if len(args) > 1 {
				if limit, ok := args[1].(float64); ok {
					readLimit = int64(limit)
				}
			}

			reader, err := gzip.NewReader(strings.NewReader(argData))
			if err != nil {
				return "", err
			}
			limitReader := io.LimitReader(reader, readLimit)

			data, err := io.ReadAll(limitReader)
			if err != nil && err != io.EOF {
				_ = reader.Close()

				return "", err
			}
			_ = reader.Close()

			return string(data), nil
		}))
	MustAddFunction(NewWithPositionalArgs("zlib", 1, true, func(args ...interface{}) (interface{}, error) {
		buffer := &bytes.Buffer{}
		writer := zlib.NewWriter(buffer)
		if _, err := writer.Write([]byte(args[0].(string))); err != nil {
			_ = writer.Close()
			return "", err
		}
		_ = writer.Close()

		return buffer.String(), nil
	}))
	MustAddFunction(NewWithSingleSignature("zlib_decode",
		"(data string, optionalReadLimit int) string",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) == 0 {
				return nil, ErrInvalidDslFunction
			}

			argData := toString(args[0])
			readLimit := DefaultMaxDecompressionSize

			if len(args) > 1 {
				if limit, ok := args[1].(float64); ok {
					readLimit = int64(limit)
				}
			}

			reader, err := zlib.NewReader(strings.NewReader(argData))
			if err != nil {
				return "", err
			}
			limitReader := io.LimitReader(reader, readLimit)

			data, err := io.ReadAll(limitReader)
			if err != nil && err != io.EOF {
				_ = reader.Close()

				return "", err
			}
			_ = reader.Close()

			return string(data), nil
		}))

	MustAddFunction(NewWithPositionalArgs("deflate", 1, true, func(args ...interface{}) (interface{}, error) {
		buffer := &bytes.Buffer{}
		writer, err := flate.NewWriter(buffer, -1)
		if err != nil {
			return "", err
		}
		if _, err := writer.Write([]byte(args[0].(string))); err != nil {
			_ = writer.Close()
			return "", err
		}
		_ = writer.Close()

		return buffer.String(), nil
	}))
	MustAddFunction(NewWithSingleSignature("inflate",
		"(data string, optionalReadLimit int) string",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) == 0 {
				return nil, ErrInvalidDslFunction
			}

			argData := toString(args[0])
			readLimit := DefaultMaxDecompressionSize

			if len(args) > 1 {
				if limit, ok := args[1].(float64); ok {
					readLimit = int64(limit)
				}
			}

			reader := flate.NewReader(strings.NewReader(argData))
			limitReader := io.LimitReader(reader, readLimit)

			data, err := io.ReadAll(limitReader)
			if err != nil && err != io.EOF {
				_ = reader.Close()

				return "", err
			}
			_ = reader.Close()

			return string(data), nil
		}))

	MustAddFunction(NewWithSingleSignature("date_time",
		"(dateTimeFormat string, optionalUnixTime interface{}) string",
		false,
		func(arguments ...interface{}) (interface{}, error) {
			dateTimeFormat := toString(arguments[0])
			dateTimeFormatFragment := dateFormatRegex.FindAllStringSubmatch(dateTimeFormat, -1)

			argumentsSize := len(arguments)
			if argumentsSize < 1 && argumentsSize > 2 {
				return nil, ErrInvalidDslFunction
			}

			currentTime, err := parseTimeOrNow(arguments)
			if err != nil {
				return nil, err
			}

			if len(dateTimeFormatFragment) > 0 {
				return doSimpleTimeFormat(dateTimeFormatFragment, currentTime, dateTimeFormat)
			} else {
				return currentTime.Format(dateTimeFormat), nil
			}
		}))
	MustAddFunction(NewWithPositionalArgs("base64_py", 1, true, func(args ...interface{}) (interface{}, error) {
		// python encodes to base64 with lines of 76 bytes terminated by new line "\n"
		stdBase64 := base64.StdEncoding.EncodeToString([]byte(toString(args[0])))
		return insertInto(stdBase64, 76, '\n'), nil
	}))
	MustAddFunction(NewWithPositionalArgs("base64_decode", 1, true, func(args ...interface{}) (interface{}, error) {
		data, err := base64.StdEncoding.DecodeString(toString(args[0]))
		return string(data), err
	}))
	MustAddFunction(NewWithSingleSignature("url_encode",
		"(s string, optionalEncodeAllSpecialChars bool) string",
		true,
		func(args ...interface{}) (interface{}, error) {
			var encodeAllChars bool
			s := toString(args[0])

			if len(args) > 1 {
				switch v := args[1].(type) {
				case bool:
					encodeAllChars = v
				case int, int64:
					encodeAllChars = v == 1
				}
			}

			shouldEscape := func(c rune, encodeAllChars bool) bool {
				isAlphanums := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
				if encodeAllChars {
					return isAlphanums
				}

				return isAlphanums || (c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')')
			}

			var result strings.Builder
			for _, c := range s {
				if shouldEscape(c, encodeAllChars) {
					result.WriteRune(c)
				} else {
					for _, b := range []byte(string(c)) {
						result.WriteString(fmt.Sprintf("%%%02X", b))
					}
				}
			}
			return result.String(), nil
		},
	))
	MustAddFunction(NewWithPositionalArgs("url_decode", 1, true, func(args ...interface{}) (interface{}, error) {
		s := toString(args[0])
		var result strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '%' && i+2 < len(s) {
				if hex, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					result.WriteByte(byte(hex))
					i += 2
				} else {
					result.WriteByte(s[i])
				}
			} else {
				result.WriteByte(s[i])
			}
		}
		return result.String(), nil
	}))
	MustAddFunction(NewWithMultipleSignatures("hex_encode", []string{
		"(data interface{}) interface{}",
		"(data interface{}, optionalFormat string) interface{}"},
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 1 || len(args) > 2 {
				return nil, ErrInvalidDslFunction
			}

			data := args[0]
			if len(args) == 1 {
				// Default behavior: standard hex format
				return hexutil.Encode(data), nil
			}

			// Optional format parameter
			format := toString(args[1])
			return hexutil.Encode(data, format), nil
		}))
	MustAddFunction(NewWithPositionalArgs("hex_decode", 1, true, func(args ...interface{}) (interface{}, error) {
		decodeString, err := hex.DecodeString(toString(args[0]))
		return string(decodeString), err
	}))
	MustAddFunction(NewWithPositionalArgs("hmac", 3, true, func(args ...interface{}) (interface{}, error) {
		hashAlgorithm := args[0]
		data := args[1].(string)
		secretKey := args[2].(string)

		var hashFunction func() hash.Hash
		switch hashAlgorithm {
		case "sha1", "sha-1":
			hashFunction = sha1.New
		case "sha256", "sha-256":
			hashFunction = sha256.New
		case "sha512", "sha-512":
			hashFunction = sha512.New
		default:
			return nil, fmt.Errorf("unsupported hash algorithm: '%s'", hashAlgorithm)
		}

		h := hmac.New(hashFunction, []byte(secretKey))
		h.Write([]byte(data))
		return hex.EncodeToString(h.Sum(nil)), nil
	}))
	MustAddFunction(NewWithSingleSignature("html_escape",
		"(s string, optionalConvertAllChars bool) string",
		true,
		func(args ...interface{}) (interface{}, error) {
			s := toString(args[0])
			if len(args) > 1 {
				convertAllChars := toBool(args[1])
				if convertAllChars {
					return strToNumEntities(s), nil
				}
			}

			return html.EscapeString(s), nil
		}))
	MustAddFunction(NewWithPositionalArgs("html_unescape", 1, true, func(args ...interface{}) (interface{}, error) {
		return html.UnescapeString(toString(args[0])), nil
	}))
	MustAddFunction(NewWithPositionalArgs("md5", 1, true, func(args ...interface{}) (interface{}, error) {
		return toHexEncodedHash(md5.New(), toString(args[0]))
	}))
	MustAddFunction(NewWithPositionalArgs("sha512", 1, true, func(args ...interface{}) (interface{}, error) {
		return toHexEncodedHash(sha512.New(), toString(args[0]))
	}))
	MustAddFunction(NewWithPositionalArgs("sha256", 1, true, func(args ...interface{}) (interface{}, error) {
		return toHexEncodedHash(sha256.New(), toString(args[0]))
	}))
	MustAddFunction(NewWithPositionalArgs("sha1", 1, true, func(args ...interface{}) (interface{}, error) {
		return toHexEncodedHash(sha1.New(), toString(args[0]))
	}))
	MustAddFunction(NewWithPositionalArgs("mmh3", 1, true, func(args ...interface{}) (interface{}, error) {
		hasher := murmur3.New32WithSeed(0)
		hasher.Write([]byte(fmt.Sprint(args[0]))) //nolint
		return fmt.Sprintf("%d", int32(hasher.Sum32())), nil
	}))
	MustAddFunction(NewWithPositionalArgs("contains", 2, true, func(args ...interface{}) (interface{}, error) {
		return strings.Contains(toString(args[0]), toString(args[1])), nil
	}))
	MustAddFunction(NewWithSingleSignature("contains_all",
		"(body interface{}, substrs ...string) bool",
		true,
		func(arguments ...interface{}) (interface{}, error) {
			body := toString(arguments[0])
			for _, value := range arguments[1:] {
				if !strings.Contains(body, toString(value)) {
					return false, nil
				}
			}
			return true, nil
		}))
	MustAddFunction(NewWithSingleSignature("contains_any",
		"(body interface{}, substrs ...string) bool",
		true,
		func(arguments ...interface{}) (interface{}, error) {
			body := toString(arguments[0])
			for _, value := range arguments[1:] {
				if strings.Contains(body, toString(value)) {
					return true, nil
				}
			}
			return false, nil
		}))
	MustAddFunction(NewWithSingleSignature("starts_with",
		"(str string, prefix ...string) bool",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}
			for _, prefix := range args[1:] {
				if strings.HasPrefix(toString(args[0]), toString(prefix)) {
					return true, nil
				}
			}
			return false, nil
		}))
	MustAddFunction(NewWithSingleSignature("line_starts_with",
		"(str string, prefix ...string) bool",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}
			for _, line := range strings.Split(toString(args[0]), "\n") {
				for _, prefix := range args[1:] {
					if strings.HasPrefix(line, toString(prefix)) {
						return true, nil
					}
				}
			}
			return false, nil
		}))
	MustAddFunction(NewWithSingleSignature("ends_with",
		"(str string, suffix ...string) bool",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}
			for _, suffix := range args[1:] {
				if strings.HasSuffix(toString(args[0]), toString(suffix)) {
					return true, nil
				}
			}
			return false, nil
		}))
	MustAddFunction(NewWithSingleSignature("line_ends_with",
		"(str string, suffix ...string) bool",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}
			for _, line := range strings.Split(toString(args[0]), "\n") {
				for _, suffix := range args[1:] {
					if strings.HasSuffix(line, toString(suffix)) {
						return true, nil
					}
				}
			}
			return false, nil
		}))
	MustAddFunction(NewWithSingleSignature("concat",
		"(args ...interface{}) string",
		true,
		func(arguments ...interface{}) (interface{}, error) {
			builder := &strings.Builder{}
			for _, argument := range arguments {
				builder.WriteString(toString(argument))
			}
			return builder.String(), nil
		}))
	MustAddFunction(NewWithMultipleSignatures("split", []string{
		"(input string, n int) []string",
		"(input string, separator string, optionalChunkSize) []string"},
		true,
		func(arguments ...interface{}) (interface{}, error) {
			argumentsSize := len(arguments)
			switch argumentsSize {
			case 2:
				input := toString(arguments[0])
				separatorOrCount := toString(arguments[1])

				count, err := strconv.Atoi(separatorOrCount)
				if err != nil {
					return strings.Split(input, separatorOrCount), nil
				}
				return toChunks(input, count), nil
			case 3:
				input := toString(arguments[0])
				separator := toString(arguments[1])
				count, err := strconv.Atoi(toString(arguments[2]))
				if err != nil {
					return nil, ErrInvalidDslFunction
				}
				return strings.SplitN(input, separator, count), nil
			default:
				return nil, ErrInvalidDslFunction
			}
		}))
	MustAddFunction(NewWithMultipleSignatures("join", []string{
		"(separator string, elements ...interface{}) string",
		"(separator string, elements []interface{}) string"},
		true,
		func(arguments ...interface{}) (interface{}, error) {
			argumentsSize := len(arguments)
			switch {
			case argumentsSize < 2:
				return nil, ErrInvalidDslFunction
			case argumentsSize == 2:
				separator := toString(arguments[0])
				elements, ok := arguments[1].([]string)

				if !ok {
					return nil, errkit.New("cannot cast elements into string")
				}

				return strings.Join(elements, separator), nil
			default:
				separator := toString(arguments[0])
				elements := arguments[1:argumentsSize]

				stringElements := make([]string, 0, argumentsSize)
				for _, element := range elements {
					if _, ok := element.([]string); ok {
						return nil, errkit.New("cannot use join on more than one slice element")
					}

					stringElements = append(stringElements, toString(element))
				}
				return strings.Join(stringElements, separator), nil
			}
		}))
	MustAddFunction(NewWithPositionalArgs("regex", 2, true, func(args ...interface{}) (interface{}, error) {
		compiled, err := regexp.Compile(toString(args[0]))
		if err != nil {
			return nil, err
		}
		return compiled.MatchString(toString(args[1])), nil
	}))
	MustAddFunction(NewWithSingleSignature("regex_all",
		"(pattern string, inputs ...string) bool",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}

			compiled, err := regexp.Compile(toString(args[0]))
			if err != nil {
				return nil, err
			}

			for _, arg := range args[1:] {
				if !compiled.MatchString(toString(arg)) {
					return false, nil
				}
			}

			return true, nil
		}))
	MustAddFunction(NewWithSingleSignature("regex_any",
		"(pattern string, inputs ...string) bool",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}

			pattern := toString(args[0])
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}

			for _, arg := range args[1:] {
				if compiled.MatchString(toString(arg)) {
					return true, nil
				}
			}

			return false, nil
		}))
	MustAddFunction(NewWithSingleSignature("equals_any",
		"(s interface{}, subs ...interface{}) bool",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}

			s := toString(args[0])

			for _, arg := range args[1:] {
				if toString(arg) == s {
					return true, nil
				}
			}

			return false, nil
		}))
	MustAddFunction(NewWithPositionalArgs("remove_bad_chars", 2, true, func(args ...interface{}) (interface{}, error) {
		input := toString(args[0])
		badChars := toString(args[1])
		return TrimAll(input, badChars), nil
	}))
	MustAddFunction(NewWithSingleSignature("rand_char",
		"(optionalCharSet string) string",
		false,
		func(args ...interface{}) (interface{}, error) {
			charSet := letters + numbers

			argSize := len(args)
			if argSize != 0 && argSize != 1 {
				return nil, ErrInvalidDslFunction
			}

			if argSize >= 1 {
				inputCharSet := toString(args[0])
				if strings.TrimSpace(inputCharSet) != "" {
					charSet = inputCharSet
				}
			}
			rint, err := randint.IntN(len(charSet))
			return string(charSet[rint]), err
		}))
	MustAddFunction(NewWithSingleSignature("rand_base",
		"(length uint, optionalCharSet string) string",
		false,
		func(args ...interface{}) (interface{}, error) {
			var length int
			charSet := letters + numbers

			argSize := len(args)
			if argSize < 1 || argSize > 3 {
				return nil, ErrInvalidDslFunction
			}

			length = int(args[0].(float64))

			if argSize == 2 {
				inputCharSet := toString(args[1])
				if strings.TrimSpace(inputCharSet) != "" {
					charSet = inputCharSet
				}
			}
			return RandSeq(charSet, length), nil
		}))
	MustAddFunction(NewWithSingleSignature("rand_text_alphanumeric",
		"(length uint, optionalBadChars string) string",
		false,
		func(args ...interface{}) (interface{}, error) {
			length := 0
			badChars := ""

			argSize := len(args)
			if argSize != 1 && argSize != 2 {
				return nil, ErrInvalidDslFunction
			}

			length = int(args[0].(float64))

			if argSize == 2 {
				badChars = toString(args[1])
			}
			chars := TrimAll(letters+numbers, badChars)
			return RandSeq(chars, length), nil
		}))
	MustAddFunction(NewWithSingleSignature("rand_text_alpha",
		"(length uint, optionalBadChars string) string",
		false,
		func(args ...interface{}) (interface{}, error) {
			var length int
			badChars := ""

			argSize := len(args)
			if argSize != 1 && argSize != 2 {
				return nil, ErrInvalidDslFunction
			}

			length = int(args[0].(float64))

			if argSize == 2 {
				badChars = toString(args[1])
			}
			chars := TrimAll(letters, badChars)
			return RandSeq(chars, length), nil
		}))
	MustAddFunction(NewWithSingleSignature("rand_text_numeric",
		"(length uint, optionalBadNumbers string) string",
		false,
		func(args ...interface{}) (interface{}, error) {
			argSize := len(args)
			if argSize != 1 && argSize != 2 {
				return nil, ErrInvalidDslFunction
			}

			length := int(args[0].(float64))
			badNumbers := ""

			if argSize == 2 {
				badNumbers = toString(args[1])
			}

			chars := TrimAll(numbers, badNumbers)
			return RandSeq(chars, length), nil
		}))
	MustAddFunction(NewWithSingleSignature("rand_int",
		"(optionalMin, optionalMax uint) int",
		false,
		func(args ...interface{}) (interface{}, error) {
			argSize := len(args)
			if argSize > 2 {
				return nil, ErrInvalidDslFunction
			}

			min := 0
			max := math.MaxInt32

			if argSize >= 1 {
				min = int(args[0].(float64))
			}
			if argSize == 2 {
				max = int(args[1].(float64))
			}

			rint, err := randint.IntN(max - min)
			return rint + min, err
		}))
	MustAddFunction(NewWithSingleSignature("rand_ip",
		"(cidr ...string) string",
		false,
		func(args ...interface{}) (interface{}, error) {
			if len(args) == 0 {
				return nil, ErrInvalidDslFunction
			}
			var cidrs []string
			for _, arg := range args {
				cidrs = append(cidrs, arg.(string))
			}
			return randomip.GetRandomIPWithCidr(cidrs...)
		}))
	MustAddFunction(NewWithPositionalArgs("generate_java_gadget", 3, true, func(args ...interface{}) (interface{}, error) {
		gadget := args[0].(string)
		cmd := args[1].(string)
		encoding := args[2].(string)
		data := deserialization.GenerateJavaGadget(gadget, cmd, encoding)
		return data, nil
	}))
	MustAddFunction(NewWithPositionalArgs("generate_dotnet_gadget", 4, true, func(args ...interface{}) (interface{}, error) {
		gadget := args[0].(string)
		cmd := args[1].(string)
		formatter := args[2].(string)
		encoding := args[3].(string)
		data := deserialization.GenerateDotNetGadget(gadget, cmd, formatter, encoding)
		return data, nil
	}))
	MustAddFunction(NewWithSingleSignature("unix_time",
		"(optionalSeconds uint) float64",
		false,
		func(args ...interface{}) (interface{}, error) {
			seconds := 0

			argSize := len(args)
			if argSize != 0 && argSize != 1 {
				return nil, ErrInvalidDslFunction
			} else if argSize == 1 {
				seconds = int(args[0].(float64))
			}

			offset := time.Now().Add(time.Duration(seconds) * time.Second)
			return float64(offset.Unix()), nil
		}))
	MustAddFunction(NewWithSingleSignature("to_unix_time",
		"(input string, optionalLayout string) int64",
		true,
		func(args ...interface{}) (interface{}, error) {
			input := toString(args[0])

			nr, err := strconv.ParseFloat(input, 64)
			if err == nil {
				return int64(nr), nil
			}

			if len(args) == 1 {
				for _, layout := range defaultDateTimeLayouts {
					parsedTime, err := time.Parse(layout, input)
					if err == nil {
						return parsedTime.Unix(), nil
					}
				}
				return nil, fmt.Errorf("could not parse the current input with the default layouts")
			} else if len(args) == 2 {
				layout := toString(args[1])
				parsedTime, err := time.Parse(layout, input)
				if err != nil {
					return nil, fmt.Errorf("could not parse the current input with the '%s' layout", layout)
				}
				return parsedTime.Unix(), err
			} else {
				return nil, ErrInvalidDslFunction
			}
		}))
	MustAddFunction(NewWithSingleSignature("wait_for",
		"(seconds uint)",
		false,
		func(args ...interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, ErrInvalidDslFunction
			}
			seconds := args[0].(float64)
			time.Sleep(time.Duration(seconds) * time.Second)
			return true, nil
		}))
	MustAddFunction(NewWithSingleSignature("compare_versions",
		"(firstVersion, constraints ...string) bool",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}

			firstParsed, parseErr := version.NewVersion(toString(args[0]))
			if parseErr != nil {
				return nil, errkit.Combine(ErrParsingArg, parseErr)
			}

			var versionConstraints []string
			for _, constraint := range args[1:] {
				versionConstraints = append(versionConstraints, toString(constraint))
			}
			constraint, constraintErr := version.NewConstraint(strings.Join(versionConstraints, ","))
			if constraintErr != nil {
				return nil, constraintErr
			}
			result := constraint.Check(firstParsed)
			return result, nil
		}))
	MustAddFunction(NewWithPositionalArgs("padding", 4, true, func(args ...interface{}) (interface{}, error) {
		// padding('Test String', 'A', 50, 'prefix') // will pad "Test String" up to 50 characters with "A" as padding byte, prefixing it.
		bLen := 0
		switch value := args[2].(type) {
		case float64:
			bLen = int(value)
		case int:
			bLen = value
		default:
			strLen := toString(args[2])
			floatVal, err := strconv.ParseFloat(strLen, 64)
			if err != nil {
				return nil, err
			}
			bLen = int(floatVal)
		}
		if bLen == 0 {
			return nil, errkit.New("invalid padding length")
		}
		bByte := []byte(toString(args[1]))
		if len(bByte) == 0 {
			return nil, errkit.New("invalid padding byte")
		}
		bData := []byte(toString(args[0]))
		dataLen := len(bData)
		if dataLen >= bLen {
			return toString(bData), nil // Note: if given string is longer than the desired length, it will not be truncated
		}

		padMode, ok := args[3].(string)
		if !ok || (padMode != "prefix" && padMode != "suffix") {
			return nil, errkit.New("padding mode must be 'prefix' or 'suffix'")
		}

		paddingLen := bLen - dataLen
		padding := make([]byte, paddingLen)
		for i := 0; i < paddingLen; i++ {
			padding[i] = bByte[i%len(bByte)]
		}

		if padMode == "prefix" {
			return toString(append(padding, bData...)), nil
		} else { // suffix
			return toString(append(bData, padding...)), nil
		}
	}))

	MustAddFunction(NewWithSingleSignature("print_debug",
		"(args ...interface{})",
		false,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 1 {
				return nil, ErrInvalidDslFunction
			}
			if PrintDebugCallback != nil {
				if err := PrintDebugCallback(args...); err != nil {
					return nil, err
				}
			} else {
				gologger.Info().Msgf("print_debug value: %s", fmt.Sprint(args))
			}
			return true, nil
		}))
	MustAddFunction(NewWithPositionalArgs("to_number", 1, true, func(args ...interface{}) (interface{}, error) {
		argStr := toString(args[0])
		if govalidator.IsInt(argStr) {
			sint, err := strconv.Atoi(argStr)
			return float64(sint), err
		} else if govalidator.IsFloat(argStr) {
			sint, err := strconv.ParseFloat(argStr, 64)
			return float64(sint), err
		}
		return nil, fmt.Errorf("%v could not be converted to int", argStr)
	}))
	MustAddFunction(NewWithPositionalArgs("to_string", 1, true, func(args ...interface{}) (interface{}, error) {
		return toString(args[0]), nil
	}))
	MustAddFunction(NewWithPositionalArgs("to_bool", 1, true, func(args ...interface{}) (interface{}, error) {
		return toBool(args[0]), nil
	}))
	MustAddFunction(NewWithPositionalArgs("dec_to_hex", 1, true, func(args ...interface{}) (interface{}, error) {
		if number, ok := args[0].(float64); ok {
			hexNum := strconv.FormatInt(int64(number), 16)
			return toString(hexNum), nil
		}
		return nil, fmt.Errorf("invalid number: %T", args[0])
	}))
	MustAddFunction(NewWithPositionalArgs("hex_to_dec", 1, true, func(args ...interface{}) (interface{}, error) {
		return stringNumberToDecimal(args, "0x", 16)
	}))
	MustAddFunction(NewWithPositionalArgs("oct_to_dec", 1, true, func(args ...interface{}) (interface{}, error) {
		return stringNumberToDecimal(args, "0o", 8)
	}))
	MustAddFunction(NewWithPositionalArgs("bin_to_dec", 1, true, func(args ...interface{}) (interface{}, error) {
		return stringNumberToDecimal(args, "0b", 2)
	}))
	MustAddFunction(NewWithSingleSignature("substr",
		"(str string, start int, optionalEnd int)",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}
			argStr := toString(args[0])
			if len(argStr) == 0 {
				return nil, errkit.New("empty string")
			}
			start, err := strconv.Atoi(toString(args[1]))
			if err != nil {
				return nil, errkit.Wrap(err, "invalid start position")
			}
			if start > len(argStr) {
				return nil, errkit.New("start position bigger than slice length")
			}
			if len(args) == 2 {
				return argStr[start:], nil
			}

			end, err := strconv.Atoi(toString(args[2]))
			if err != nil {
				return nil, errkit.New("invalid end position")
			}
			if end < 0 {
				return nil, errkit.New("negative end position")
			}
			if end < start {
				return nil, errkit.New("end position before start")
			}
			if end > len(argStr) {
				return nil, errkit.New("end position bigger than slice length start")
			}
			return argStr[start:end], nil
		}))
	MustAddFunction(NewWithPositionalArgs("aes_cbc", 3, false, func(args ...interface{}) (interface{}, error) {
		bKey := []byte(args[1].(string))
		bIV := []byte(args[2].(string))
		bPlaintext := pkcs5padding([]byte(args[0].(string)), aes.BlockSize, len(args[0].(string)))
		block, _ := aes.NewCipher(bKey)
		ciphertext := make([]byte, len(bPlaintext))
		mode := cipher.NewCBCEncrypter(block, bIV)
		mode.CryptBlocks(ciphertext, bPlaintext)
		return ciphertext, nil
	}))
	MustAddFunction(NewWithPositionalArgs("aes_gcm", 2, false, func(args ...interface{}) (interface{}, error) {
		key := args[0].(string)
		value := args[1].(string)

		c, err := aes.NewCipher([]byte(key))
		if nil != err {
			return "", err
		}
		gcm, err := cipher.NewGCM(c)
		if nil != err {
			return "", err
		}

		nonce := make([]byte, gcm.NonceSize())

		if _, err = rand.Read(nonce); err != nil {
			return "", err
		}
		data := gcm.Seal(nonce, nonce, []byte(value), nil)
		return data, nil
	}))
	MustAddFunction(NewWithSingleSignature("generate_jwt",
		"(jsonString, algorithm, optionalSignature string, optionalMaxAgeUnix interface{}) string",
		true,
		func(args ...interface{}) (interface{}, error) {
			var algorithm string
			var optionalSignature []byte
			var optionalMaxAgeUnix time.Time

			var signOpts []jwt.SignOption
			var jsonData jwt.Map

			argSize := len(args)

			if argSize < 2 || argSize > 4 {
				return nil, ErrInvalidDslFunction
			}
			jsonString := args[0].(string)

			err := json.Unmarshal([]byte(jsonString), &jsonData)
			if err != nil {
				return nil, err
			}

			var jwtAlgorithm jwt.Alg
			alg := args[1].(string)
			algorithm = strings.ToUpper(alg)

			switch algorithm {
			case "":
				jwtAlgorithm = jwt.NONE
			case "HS256":
				jwtAlgorithm = jwt.HS256
			case "HS384":
				jwtAlgorithm = jwt.HS384
			case "HS512":
				jwtAlgorithm = jwt.HS512
			case "RS256":
				jwtAlgorithm = jwt.RS256
			case "RS384":
				jwtAlgorithm = jwt.RS384
			case "RS512":
				jwtAlgorithm = jwt.RS512
			case "PS256":
				jwtAlgorithm = jwt.PS256
			case "PS384":
				jwtAlgorithm = jwt.PS384
			case "PS512":
				jwtAlgorithm = jwt.PS512
			case "ES256":
				jwtAlgorithm = jwt.ES256
			case "ES384":
				jwtAlgorithm = jwt.ES384
			case "ES512":
				jwtAlgorithm = jwt.ES512
			case "EDDSA":
				jwtAlgorithm = jwt.EdDSA
			}

			if isjwtAlgorithmNone(alg) {
				jwtAlgorithm = &algNONE{algValue: alg}
			}
			if jwtAlgorithm == nil {
				return nil, fmt.Errorf("invalid algorithm: %s", algorithm)
			}

			if argSize > 2 {
				optionalSignature = []byte(args[2].(string))
			}

			if argSize > 3 {
				times := make([]interface{}, 2)
				times[0] = nil
				times[1] = args[3]

				optionalMaxAgeUnix, err = parseTimeOrNow(times)
				if err != nil {
					return nil, err
				}

				duration := time.Until(optionalMaxAgeUnix)
				signOpts = append(signOpts, jwt.MaxAge(duration))
			}

			return jwt.Sign(jwtAlgorithm, optionalSignature, jsonData, signOpts...)
		}))
	MustAddFunction(NewWithPositionalArgs("json_minify", 1, true, func(args ...interface{}) (interface{}, error) {
		var data map[string]interface{}

		err := json.Unmarshal([]byte(args[0].(string)), &data)
		if err != nil {
			return nil, err
		}

		minified, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		return string(minified), nil
	}))
	MustAddFunction(NewWithPositionalArgs("json_prettify", 1, true, func(args ...interface{}) (interface{}, error) {
		var buf bytes.Buffer

		err := json.Indent(&buf, []byte(args[0].(string)), "", "    ")
		if err != nil {
			return nil, err
		}

		return buf.String(), nil
	}))
	MustAddFunction(NewWithPositionalArgs("ip_format", 2, true, func(args ...interface{}) (interface{}, error) {
		ipFormat, err := strconv.ParseInt(toString(args[1]), 10, 64)
		if err != nil {
			return nil, err
		}
		if ipFormat <= 0 || ipFormat > 11 {
			return nil, fmt.Errorf("invalid format, format must be in range 1-11")
		}
		formattedIps := mapcidr.AlterIP(toString(args[0]), []string{toString(args[1])}, 3, false)
		if len(formattedIps) == 0 {
			return nil, fmt.Errorf("no formatted IP returned")
		}
		return formattedIps[0], nil
	}))
	MustAddFunction(NewWithSingleSignature("llm_prompt",
		"(prompt string, optionalModel string) string",
		false,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 1 {
				return nil, ErrInvalidDslFunction
			}

			prompt, ok := args[0].(string)
			if !ok {
				return nil, errors.New("invalid prompt")
			}

			model := openai.GPT4oMini // default model
			if len(args) == 2 {
				if model, ok = args[1].(string); !ok {
					return nil, errors.New("invalid model")
				}
			}

			return llm.Query(prompt, model)
		}))
	MustAddFunction(NewWithPositionalArgs("unpack", 2, true, func(args ...interface{}) (interface{}, error) {
		// format as string (ref: https://docs.python.org/3/library/struct.html#format-characters)
		format, ok := args[0].(string)
		if !ok {
			return nil, errors.New("invalid format")
		}
		// binary packed data
		data, ok := args[1].(string)
		if !ok {
			return nil, errors.New("invalid data")
		}
		// convert flat format into slice (eg. ">I" => [">","I"])
		var formatParts []string
		for idx := range format {
			formatParts = append(formatParts, string(format[idx]))
		}
		// the dsl function supports unpacking only one type at a time
		unpackedData, err := gostruct.UnPack(formatParts, []byte(data))
		if len(unpackedData) > 0 {
			return unpackedData[0], err
		}
		return nil, errors.New("no result")
	}))
	MustAddFunction(NewWithSingleSignature("xor",
		"(args ...interface{}) interface{}",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, errors.New("at least two arguments needed")
			}

			n := -1
			for _, arg := range args {
				var b []byte
				switch v := arg.(type) {
				case string:
					b = []byte(v)
				case []byte:
					b = v
				default:
					return nil, fmt.Errorf("invalid argument type %T", arg)
				}
				if n == -1 {
					n = len(b)
				} else if len(b) != n {
					return nil, errors.New("all arguments must have the same length")
				}
			}

			result := make([]byte, n)
			for i := 0; i < n; i++ {
				for _, arg := range args {
					b, ok := arg.([]byte)
					if !ok {
						b = []byte(arg.(string))
					}
					result[i] ^= b[i]
				}
			}

			return result, nil
		}))
	MustAddFunction(NewWithSingleSignature("public_ip",
		"() string",
		true,
		func(args ...interface{}) (interface{}, error) {
			publicIP := GetPublicIP()
			if publicIP == "" {
				return nil, errors.New("could not retrieve public ip")
			}
			return publicIP, nil
		}))

	MustAddFunction(NewWithPositionalArgs("jarm", 1, true, func(args ...interface{}) (interface{}, error) {
		host, ok := args[0].(string)
		if !ok {
			return nil, errors.New("invalid target")
		}
		hostname, portRaw, err := net.SplitHostPort(host)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portRaw)
		if err != nil {
			return nil, err
		}
		// pick the first available proxy from common env vars (case-insensitive)
		proxy := firstNonEmptyEnv("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
		if proxy != "" {
			socks5Dialer, err := connpool.NewCreateSOCKS5Dialer(proxy)
			if err != nil {
				return nil, err
			}
			return jarm.HashWithDialer(socks5Dialer, hostname, port, 10)
		}
		return jarm.HashWithDialer(nil, hostname, port, 10)
	}))

	MustAddFunction(NewWithSingleSignature("count",
		"(str, substr string) int",
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 2 {
				return nil, ErrInvalidDslFunction
			}

			str := toString(args[0])
			substr := toString(args[1])

			return strings.Count(str, substr), nil
		},
	))

	MustAddFunction(NewWithSingleSignature("to_title",
		"(s, optionalLang string) string",
		true,
		func(args ...interface{}) (interface{}, error) {
			var lang = language.Und
			var s string
			var err error

			argSize := len(args)
			if argSize < 1 {
				return nil, ErrInvalidDslFunction
			}
			s = toString(args[0])

			if argSize >= 2 {
				lang, err = language.Parse(toString(args[1]))
				if err != nil {
					lang = language.Und
				}
			}

			return cases.Title(lang).String(s), nil
		},
	))

	MustAddFunction(NewWithSingleSignature("cookie_unsign",
		"(s string) string", false,
		func(args ...interface{}) (interface{}, error) {
			argSize := len(args)
			if argSize < 1 {
				return nil, ErrInvalidDslFunction
			}
			s := toString(args[0])

			wl := monster.NewWordlist()
			if err := wl.LoadDefault(); err != nil {
				return s, errors.New("could not load default wordlist")
			}

			c := monster.NewCookie(s)
			if !c.Decode() {
				return s, errors.New("could not decode cookie")
			}

			if cookie, ok := c.Unsign(wl, 100); ok {
				return string(cookie), nil
			}

			return s, errors.New("could not unsign cookie")
		},
	))

	MustAddFunction(NewWithPositionalArgs("gzip_mtime", 1, true, func(args ...interface{}) (interface{}, error) {
		if len(args) == 0 {
			return nil, ErrInvalidDslFunction
		}

		argData := toString(args[0])
		readLimit := DefaultMaxDecompressionSize

		reader, err := gzip.NewReader(io.LimitReader(strings.NewReader(argData), readLimit))
		if err != nil {
			return "", err
		}

		var mtime int64
		if !reader.ModTime.IsZero() {
			mtime = reader.ModTime.Unix()
		}
		_ = reader.Close()

		return float64(mtime), nil
	}))

	MustAddFunction(NewWithPositionalArgs("rsa_encrypt",
		2,
		true,
		func(args ...interface{}) (interface{}, error) {
			if len(args) != 2 {
				return nil, errors.New("rsa_encrypt expects 2 arguments: plaintext, pemPublicKey")
			}

			plaintext, ok1 := args[0].(string)
			publicKeyPem, ok2 := args[1].(string)

			if !ok1 || !ok2 {
				return nil, errors.New("invalid arguments")
			}

			block, _ := pem.Decode([]byte(publicKeyPem))
			if block == nil {
				return nil, errors.New("invalid PEM format")
			}

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}

			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("not an RSA public key")
			}

			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(plaintext))
			if err != nil {
				return nil, fmt.Errorf("RSA encryption failed: %w", err)
			}
			return base64.StdEncoding.EncodeToString(ciphertext), nil
		}),
	)

	DefaultHelperFunctions = HelperFunctions()
	FunctionNames = GetFunctionNames(DefaultHelperFunctions)
}

// Helper function to generate function signatures for faker functions
func getFakerSignature(info gofakeit.Info) string {
	var params []string
	for _, p := range info.Params {
		params = append(params, fmt.Sprintf("%s %s", p.Field, p.Type))
	}
	return fmt.Sprintf("(%s) %s", strings.Join(params, ", "), info.Output)
}

func NewWithSingleSignature(name, signature string, cacheable bool, logic govaluate.ExpressionFunction) dslFunction {
	return NewWithMultipleSignatures(name, []string{signature}, cacheable, logic)
}

func NewWithMultipleSignatures(name string, signatures []string, cacheable bool, expr govaluate.ExpressionFunction) dslFunction {
	function := dslFunction{
		Name:               name,
		Signatures:         signatures,
		ExpressionFunction: expr,
		IsCacheable:        cacheable,
	}

	return function
}

func NewWithPositionalArgs(name string, numberOfArgs int, cacheable bool, expr govaluate.ExpressionFunction) dslFunction {
	function := dslFunction{
		Name:               name,
		NumberOfArgs:       numberOfArgs,
		ExpressionFunction: expr,
		IsCacheable:        cacheable,
	}
	return function
}

// FakerFunctions returns the faker functions
//
// Note: It does not support backwards compatibility for function names
func FakerFunctions() map[string]govaluate.ExpressionFunction {
	funcs := make(map[string]govaluate.ExpressionFunction)
	slug.CustomSub = map[string]string{" ": "_"}

	for _, fInfo := range gofakeit.FuncLookups {
		// NOTE(dwisiswant0): Skipping function because it not callable or the
		// output is not printable.
		hasSliceParam := false
		for _, p := range fInfo.Params {
			if strings.Contains(p.Type, "[]") {
				hasSliceParam = true
				break
			}
		}
		if hasSliceParam {
			continue
		}
		if strings.Contains(fInfo.Output, "map") {
			continue
		}

		funcName := "rand_" + slug.Make(fInfo.Display)
		fakerFunc := func(fInfo gofakeit.Info) func(args ...any) (any, error) {
			return func(args ...any) (any, error) {
				// Set function and params
				// Copied from: https://github.com/brianvoe/gofakeit/blob/e7c55ca0031ef39bb7673deedfc9f04fc17d8072/cmd/gofakeit/gofakeit.go#L112
				params := gofakeit.NewMapParams()
				paramsLen := len(fInfo.Params)
				argsLen := len(args)
				if argsLen != paramsLen {
					return nil, fmt.Errorf("expected %d arguments, got %d", paramsLen, argsLen)
				}

				if paramsLen > 0 {
					for i := 0; i < argsLen; i++ {
						if i == 0 {
							continue
						}

						// Map argument to param field
						if paramsLen >= i {
							p := fInfo.Params[i-1]
							arg := fmt.Sprintf("%v", args[i])
							params.Add(p.Field, arg)
						}
					}
				}

				value, err := fInfo.Generate(faker, params, &fInfo)
				if err != nil {
					return "", fmt.Errorf("faker error: %w", err)
				}

				return value, nil
			}
		}

		// Register the function with the DSL
		f := fakerFunc(fInfo)
		err := addFakerFunction(NewWithSingleSignature(
			funcName, getFakerSignature(fInfo), false, f,
		))
		if err != nil && !errors.Is(err, errDuplicateFunc) {
			panic(fmt.Errorf("%w (faker)", err))
		}
		funcs[funcName] = f
	}

	return funcs
}

// HelperFunctions returns the dsl helper functions
func HelperFunctions() map[string]govaluate.ExpressionFunction {
	helperFunctions := make(map[string]govaluate.ExpressionFunction)

	for _, function := range functions {
		helperFunctions[function.Name] = function.Exec
		// for backwards compatibility
		helperFunctions[strings.ReplaceAll(function.Name, "_", "")] = function.Exec
	}

	return helperFunctions
}

// AddMultiSignatureHelperFunction allows creation of additional helper functions to be supported with templates
// Deprecated: Use AddFunction(NewWithMultipleSignatures(...)) - kept for backward compatibility
func AddMultiSignatureHelperFunction(key string, signatureparts []string, cacheable bool, value func(args ...interface{}) (interface{}, error)) error {
	function := NewWithMultipleSignatures(key, signatureparts, cacheable, value)
	return AddFunction(function)
}

func GetFunctionNames(heperFunctions map[string]govaluate.ExpressionFunction) []string {
	return maputils.GetKeys(heperFunctions)
}

// GetPrintableDslFunctionSignatures returns the function signatures for the
// default DSL functions
func GetPrintableDslFunctionSignatures(noColor bool) string {
	if noColor {
		return aggregate(getDslFunctionSignatures(functions))
	}
	return aggregate(colorizeDslFunctionSignatures(functions))
}

// GetPrintableFakerDslFunctionSignatures returns the function signatures for
// the faker functions.
//
// Note: [FakerFunctions] must be called first to populate the functions
// map with the faker functions.
func GetPrintableFakerDslFunctionSignatures(noColor bool) string {
	if noColor {
		return aggregate(getDslFunctionSignatures(fakerFunctions))
	}
	return aggregate(colorizeDslFunctionSignatures(fakerFunctions))
}

func getDslFunctionSignatures(funcs []dslFunction) []string {
	var result []string
	for _, f := range funcs {
		result = append(result, f.GetSignatures()...)
	}
	return result
}

func colorizeDslFunctionSignatures(funcs []dslFunction) []string {
	signatures := getDslFunctionSignatures(funcs)

	colorToOrange := func(value string) string {
		return aurora.Index(208, value).String()
	}

	result := make([]string, 0, len(signatures))

	for _, signature := range signatures {
		subMatchSlices := funcSignatureRegex.FindAllStringSubmatch(signature, -1)
		if len(subMatchSlices) != 1 {
			result = append(result, signature)
			continue
		}
		matches := subMatchSlices[0]
		if len(matches) != 5 {
			result = append(result, signature)
			continue
		}

		functionParameters := strings.Split(matches[2], ",")

		var coloredParameterAndTypes []string
		for _, functionParameter := range functionParameters {
			functionParameter = strings.TrimSpace(functionParameter)
			paramAndType := strings.Split(functionParameter, " ")
			if len(paramAndType) == 1 {
				coloredParameterAndTypes = append(coloredParameterAndTypes, paramAndType[0])
			} else if len(paramAndType) == 2 {
				coloredParameterAndTypes = append(coloredParameterAndTypes, fmt.Sprintf("%s %s", paramAndType[0], colorToOrange(paramAndType[1])))
			}
		}

		highlightedParams := strings.TrimSpace(fmt.Sprintf("%s %s", strings.Join(coloredParameterAndTypes, ", "), colorToOrange(matches[3])))
		colorizedDslSignature := fmt.Sprintf("%s(%s)%s", aurora.BrightYellow(matches[1]).String(), highlightedParams, colorToOrange(matches[4]))

		result = append(result, colorizedDslSignature)
	}

	return result
}
