package dsl

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"html"
	"io"
	"math"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/asaskevich/govalidator"
	"github.com/hashicorp/go-version"
	"github.com/kataras/jwt"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/sashabaranov/go-openai"
	"github.com/spaolacci/murmur3"

	"github.com/projectdiscovery/dsl/deserialization"
	"github.com/projectdiscovery/dsl/randomip"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

const (
	numbers = "1234567890"
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	ErrinvalidDslFunction = errors.New("invalid DSL function signature")
	dslFunctions          map[string]dslFunction

	// FunctionNames is a list of function names for expression evaluation usages
	FunctionNames []string
	// DefaultHelperFunctions is a pre-compiled list of govaluate DSL functions
	DefaultHelperFunctions map[string]govaluate.ExpressionFunction

	funcSignatureRegex = regexp.MustCompile(`(\w+)\s*\((?:([\w\d,\s]+)\s+([.\w\d{}&*]+))?\)([\s.\w\d{}&*]+)?`)
	dateFormatRegex    = regexp.MustCompile("%([A-Za-z])")
)

type dslFunction struct {
	signatures  []string
	expressFunc govaluate.ExpressionFunction
}

var defaultDateTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02 15:04:05 Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04 Z07:00",
	"2006-01-02 15:04",
	"2006-01-02 Z07:00",
	"2006-01-02",
}

var PrintDebugCallback func(args ...interface{}) error

func init() {
	tempDslFunctions := map[string]func(string) dslFunction{
		"len": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			length := len(toString(args[0]))
			return float64(length), nil
		}),
		"to_upper": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return strings.ToUpper(toString(args[0])), nil
		}),
		"to_lower": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return strings.ToLower(toString(args[0])), nil
		}),
		"sort": makeMultiSignatureDslFunction([]string{
			"(input string) string",
			"(input number) string",
			"(elements ...interface{}) []interface{}"},
			func(args ...interface{}) (interface{}, error) {
				argCount := len(args)
				if argCount == 0 {
					return nil, ErrinvalidDslFunction
				} else if argCount == 1 {
					runes := []rune(toString(args[0]))
					sort.Slice(runes, func(i int, j int) bool {
						return runes[i] < runes[j]
					})
					return string(runes), nil
				} else {
					tokens := make([]string, 0, argCount)
					for _, arg := range args {
						tokens = append(tokens, toString(arg))
					}
					sort.Strings(tokens)
					return tokens, nil
				}
			},
		),
		"uniq": makeMultiSignatureDslFunction([]string{
			"(input string) string",
			"(input number) string",
			"(elements ...interface{}) []interface{}"},
			func(args ...interface{}) (interface{}, error) {
				argCount := len(args)
				if argCount == 0 {
					return nil, ErrinvalidDslFunction
				} else if argCount == 1 {
					builder := &strings.Builder{}
					visited := make(map[rune]struct{})
					for _, i := range toString(args[0]) {
						if _, isRuneSeen := visited[i]; !isRuneSeen {
							builder.WriteRune(i)
							visited[i] = struct{}{}
						}
					}
					return builder.String(), nil
				} else {
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
		),
		"repeat": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			count, err := strconv.Atoi(toString(args[1]))
			if err != nil {
				return nil, ErrinvalidDslFunction
			}
			return strings.Repeat(toString(args[0]), count), nil
		}),
		"replace": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
			return strings.ReplaceAll(toString(args[0]), toString(args[1]), toString(args[2])), nil
		}),
		"replace_regex": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
			compiled, err := regexp.Compile(toString(args[1]))
			if err != nil {
				return nil, err
			}
			return compiled.ReplaceAllString(toString(args[0]), toString(args[2])), nil
		}),
		"trim": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.Trim(toString(args[0]), toString(args[1])), nil
		}),
		"trim_left": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimLeft(toString(args[0]), toString(args[1])), nil
		}),
		"trim_right": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimRight(toString(args[0]), toString(args[1])), nil
		}),
		"trim_space": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return strings.TrimSpace(toString(args[0])), nil
		}),
		"trim_prefix": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimPrefix(toString(args[0]), toString(args[1])), nil
		}),
		"trim_suffix": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimSuffix(toString(args[0]), toString(args[1])), nil
		}),
		"reverse": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return stringsutil.Reverse(toString(args[0])), nil
		}),
		"base64": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return base64.StdEncoding.EncodeToString([]byte(toString(args[0]))), nil
		}),
		"gzip": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			buffer := &bytes.Buffer{}
			writer := gzip.NewWriter(buffer)
			if _, err := writer.Write([]byte(args[0].(string))); err != nil {
				_ = writer.Close()
				return "", err
			}
			_ = writer.Close()

			return buffer.String(), nil
		}),
		"gzip_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			reader, err := gzip.NewReader(strings.NewReader(args[0].(string)))
			if err != nil {
				return "", err
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				_ = reader.Close()
				return "", err
			}
			_ = reader.Close()
			return string(data), nil
		}),
		"zlib": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			buffer := &bytes.Buffer{}
			writer := zlib.NewWriter(buffer)
			if _, err := writer.Write([]byte(args[0].(string))); err != nil {
				_ = writer.Close()
				return "", err
			}
			_ = writer.Close()

			return buffer.String(), nil
		}),
		"zlib_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			reader, err := zlib.NewReader(strings.NewReader(args[0].(string)))
			if err != nil {
				return "", err
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				_ = reader.Close()
				return "", err
			}
			_ = reader.Close()
			return string(data), nil
		}),
		"date_time": makeDslWithOptionalArgsFunction(
			"(dateTimeFormat string, optionalUnixTime interface{}) string",
			func(arguments ...interface{}) (interface{}, error) {
				dateTimeFormat := toString(arguments[0])
				dateTimeFormatFragment := dateFormatRegex.FindAllStringSubmatch(dateTimeFormat, -1)

				argumentsSize := len(arguments)
				if argumentsSize < 1 && argumentsSize > 2 {
					return nil, ErrinvalidDslFunction
				}

				currentTime, err := getCurrentTimeFromUserInput(arguments)
				if err != nil {
					return nil, err
				}

				if len(dateTimeFormatFragment) > 0 {
					return doSimpleTimeFormat(dateTimeFormatFragment, currentTime, dateTimeFormat)
				} else {
					return currentTime.Format(dateTimeFormat), nil
				}
			},
		),
		"base64_py": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			// python encodes to base64 with lines of 76 bytes terminated by new line "\n"
			stdBase64 := base64.StdEncoding.EncodeToString([]byte(toString(args[0])))
			return insertInto(stdBase64, 76, '\n'), nil
		}),
		"base64_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			data, err := base64.StdEncoding.DecodeString(toString(args[0]))
			return string(data), err
		}),
		"url_encode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return url.QueryEscape(toString(args[0])), nil
		}),
		"url_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return url.QueryUnescape(toString(args[0]))
		}),
		"hex_encode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return hex.EncodeToString([]byte(toString(args[0]))), nil
		}),
		"hex_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			decodeString, err := hex.DecodeString(toString(args[0]))
			return string(decodeString), err
		}),
		"hmac": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
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
		}),
		"html_escape": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return html.EscapeString(toString(args[0])), nil
		}),
		"html_unescape": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return html.UnescapeString(toString(args[0])), nil
		}),
		"md5": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return toHexEncodedHash(md5.New(), toString(args[0]))
		}),
		"sha512": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return toHexEncodedHash(sha512.New(), toString(args[0]))
		}),
		"sha256": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return toHexEncodedHash(sha256.New(), toString(args[0]))
		}),
		"sha1": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return toHexEncodedHash(sha1.New(), toString(args[0]))
		}),
		"mmh3": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			hasher := murmur3.New32WithSeed(0)
			hasher.Write([]byte(fmt.Sprint(args[0])))
			return fmt.Sprintf("%d", int32(hasher.Sum32())), nil
		}),
		"contains": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.Contains(toString(args[0]), toString(args[1])), nil
		}),
		"contains_all": makeDslWithOptionalArgsFunction(
			"(body interface{}, substrs ...string) bool",
			func(arguments ...interface{}) (interface{}, error) {
				body := toString(arguments[0])
				for _, value := range arguments[1:] {
					if !strings.Contains(body, toString(value)) {
						return false, nil
					}
				}
				return true, nil
			}),
		"contains_any": makeDslWithOptionalArgsFunction(
			"(body interface{}, substrs ...string) bool",
			func(arguments ...interface{}) (interface{}, error) {
				body := toString(arguments[0])
				for _, value := range arguments[1:] {
					if strings.Contains(body, toString(value)) {
						return true, nil
					}
				}
				return false, nil
			}),
		"starts_with": makeDslWithOptionalArgsFunction(
			"(str string, prefix ...string) bool",
			func(args ...interface{}) (interface{}, error) {
				if len(args) < 2 {
					return nil, ErrinvalidDslFunction
				}
				for _, prefix := range args[1:] {
					if strings.HasPrefix(toString(args[0]), toString(prefix)) {
						return true, nil
					}
				}
				return false, nil
			},
		),
		"line_starts_with": makeDslWithOptionalArgsFunction(
			"(str string, prefix ...string) bool", func(args ...interface{}) (interface{}, error) {
				if len(args) < 2 {
					return nil, ErrinvalidDslFunction
				}
				for _, line := range strings.Split(toString(args[0]), "\n") {
					for _, prefix := range args[1:] {
						if strings.HasPrefix(line, toString(prefix)) {
							return true, nil
						}
					}
				}
				return false, nil
			},
		),
		"ends_with": makeDslWithOptionalArgsFunction(
			"(str string, suffix ...string) bool",
			func(args ...interface{}) (interface{}, error) {
				if len(args) < 2 {
					return nil, ErrinvalidDslFunction
				}
				for _, suffix := range args[1:] {
					if strings.HasSuffix(toString(args[0]), toString(suffix)) {
						return true, nil
					}
				}
				return false, nil
			},
		),
		"line_ends_with": makeDslWithOptionalArgsFunction(
			"(str string, suffix ...string) bool", func(args ...interface{}) (interface{}, error) {
				if len(args) < 2 {
					return nil, ErrinvalidDslFunction
				}
				for _, line := range strings.Split(toString(args[0]), "\n") {
					for _, suffix := range args[1:] {
						if strings.HasSuffix(line, toString(suffix)) {
							return true, nil
						}
					}
				}
				return false, nil
			},
		),
		"concat": makeDslWithOptionalArgsFunction(
			"(args ...interface{}) string",
			func(arguments ...interface{}) (interface{}, error) {
				builder := &strings.Builder{}
				for _, argument := range arguments {
					builder.WriteString(toString(argument))
				}
				return builder.String(), nil
			},
		),
		"split": makeMultiSignatureDslFunction([]string{
			"(input string, n int) []string",
			"(input string, separator string, optionalChunkSize) []string"},
			func(arguments ...interface{}) (interface{}, error) {
				argumentsSize := len(arguments)
				if argumentsSize == 2 {
					input := toString(arguments[0])
					separatorOrCount := toString(arguments[1])

					count, err := strconv.Atoi(separatorOrCount)
					if err != nil {
						return strings.SplitN(input, separatorOrCount, -1), nil
					}
					return toChunks(input, count), nil
				} else if argumentsSize == 3 {
					input := toString(arguments[0])
					separator := toString(arguments[1])
					count, err := strconv.Atoi(toString(arguments[2]))
					if err != nil {
						return nil, ErrinvalidDslFunction
					}
					return strings.SplitN(input, separator, count), nil
				} else {
					return nil, ErrinvalidDslFunction
				}
			},
		),
		"join": makeMultiSignatureDslFunction([]string{
			"(separator string, elements ...interface{}) string",
			"(separator string, elements []interface{}) string"},
			func(arguments ...interface{}) (interface{}, error) {
				argumentsSize := len(arguments)
				if argumentsSize < 2 {
					return nil, ErrinvalidDslFunction
				} else if argumentsSize == 2 {
					separator := toString(arguments[0])
					elements, ok := arguments[1].([]string)

					if !ok {
						return nil, errors.New("cannot cast elements into string")
					}

					return strings.Join(elements, separator), nil
				} else {
					separator := toString(arguments[0])
					elements := arguments[1:argumentsSize]

					stringElements := make([]string, 0, argumentsSize)
					for _, element := range elements {
						if _, ok := element.([]string); ok {
							return nil, errors.New("cannot use join on more than one slice element")
						}

						stringElements = append(stringElements, toString(element))
					}
					return strings.Join(stringElements, separator), nil
				}
			},
		),
		"regex": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			compiled, err := regexp.Compile(toString(args[0]))
			if err != nil {
				return nil, err
			}
			return compiled.MatchString(toString(args[1])), nil
		}),
		"regex_all": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			for _, arg := range toStringSlice(args[1]) {
				compiled, err := Regex(toString(arg))
				if err != nil {
					return nil, err
				}
				if !compiled.MatchString(toString(args[0])) {
					return false, nil
				}
			}
			return false, nil
		}),

		"regex_any": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			for _, arg := range toStringSlice(args[1]) {
				compiled, err := Regex(toString(arg))
				if err != nil {
					return nil, err
				}
				if compiled.MatchString(toString(args[0])) {
					return true, nil
				}
			}
			return false, nil
		}),

		"equals_any": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			for _, arg := range toStringSlice(args[1]) {
				if args[0] == arg {
					return true, nil
				}
			}
			return false, nil
		}),

		"remove_bad_chars": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			input := toString(args[0])
			badChars := toString(args[1])
			return trimAll(input, badChars), nil
		}),
		"rand_char": makeDslWithOptionalArgsFunction(
			"(optionalCharSet string) string",
			func(args ...interface{}) (interface{}, error) {
				charSet := letters + numbers

				argSize := len(args)
				if argSize != 0 && argSize != 1 {
					return nil, ErrinvalidDslFunction
				}

				if argSize >= 1 {
					inputCharSet := toString(args[0])
					if strings.TrimSpace(inputCharSet) != "" {
						charSet = inputCharSet
					}
				}

				return string(charSet[rand.Intn(len(charSet))]), nil
			},
		),
		"rand_base": makeDslWithOptionalArgsFunction(
			"(length uint, optionalCharSet string) string",
			func(args ...interface{}) (interface{}, error) {
				var length int
				charSet := letters + numbers

				argSize := len(args)
				if argSize < 1 || argSize > 3 {
					return nil, ErrinvalidDslFunction
				}

				length = int(args[0].(float64))

				if argSize == 2 {
					inputCharSet := toString(args[1])
					if strings.TrimSpace(inputCharSet) != "" {
						charSet = inputCharSet
					}
				}
				return randSeq(charSet, length), nil
			},
		),
		"rand_text_alphanumeric": makeDslWithOptionalArgsFunction(
			"(length uint, optionalBadChars string) string",
			func(args ...interface{}) (interface{}, error) {
				length := 0
				badChars := ""

				argSize := len(args)
				if argSize != 1 && argSize != 2 {
					return nil, ErrinvalidDslFunction
				}

				length = int(args[0].(float64))

				if argSize == 2 {
					badChars = toString(args[1])
				}
				chars := trimAll(letters+numbers, badChars)
				return randSeq(chars, length), nil
			},
		),
		"rand_text_alpha": makeDslWithOptionalArgsFunction(
			"(length uint, optionalBadChars string) string",
			func(args ...interface{}) (interface{}, error) {
				var length int
				badChars := ""

				argSize := len(args)
				if argSize != 1 && argSize != 2 {
					return nil, ErrinvalidDslFunction
				}

				length = int(args[0].(float64))

				if argSize == 2 {
					badChars = toString(args[1])
				}
				chars := trimAll(letters, badChars)
				return randSeq(chars, length), nil
			},
		),
		"rand_text_numeric": makeDslWithOptionalArgsFunction(
			"(length uint, optionalBadNumbers string) string",
			func(args ...interface{}) (interface{}, error) {
				argSize := len(args)
				if argSize != 1 && argSize != 2 {
					return nil, ErrinvalidDslFunction
				}

				length := int(args[0].(float64))
				badNumbers := ""

				if argSize == 2 {
					badNumbers = toString(args[1])
				}

				chars := trimAll(numbers, badNumbers)
				return randSeq(chars, length), nil
			},
		),
		"rand_int": makeDslWithOptionalArgsFunction(
			"(optionalMin, optionalMax uint) int",
			func(args ...interface{}) (interface{}, error) {
				argSize := len(args)
				if argSize > 2 {
					return nil, ErrinvalidDslFunction
				}

				min := 0
				max := math.MaxInt32

				if argSize >= 1 {
					min = int(args[0].(float64))
				}
				if argSize == 2 {
					max = int(args[1].(float64))
				}
				return rand.Intn(max-min) + min, nil
			},
		),
		"rand_ip": makeDslWithOptionalArgsFunction(
			"(cidr ...string) string",
			func(args ...interface{}) (interface{}, error) {
				if len(args) == 0 {
					return nil, ErrinvalidDslFunction
				}
				var cidrs []string
				for _, arg := range args {
					cidrs = append(cidrs, arg.(string))
				}
				return randomip.GetRandomIPWithCidr(cidrs...)
			}),
		"generate_java_gadget": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
			gadget := args[0].(string)
			cmd := args[1].(string)
			encoding := args[2].(string)
			data := deserialization.GenerateJavaGadget(gadget, cmd, encoding)
			return data, nil
		}),
		"unix_time": makeDslWithOptionalArgsFunction(
			"(optionalSeconds uint) float64",
			func(args ...interface{}) (interface{}, error) {
				seconds := 0

				argSize := len(args)
				if argSize != 0 && argSize != 1 {
					return nil, ErrinvalidDslFunction
				} else if argSize == 1 {
					seconds = int(args[0].(float64))
				}

				offset := time.Now().Add(time.Duration(seconds) * time.Second)
				return float64(offset.Unix()), nil
			},
		),
		"to_unix_time": makeDslWithOptionalArgsFunction(
			"(input string, optionalLayout string) int64",
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
					return nil, ErrinvalidDslFunction
				}
			},
		),
		"wait_for": makeDslWithOptionalArgsFunction(
			"(seconds uint)",
			func(args ...interface{}) (interface{}, error) {
				if len(args) != 1 {
					return nil, ErrinvalidDslFunction
				}
				seconds := args[0].(float64)
				time.Sleep(time.Duration(seconds) * time.Second)
				return true, nil
			},
		),
		"compare_versions": makeDslWithOptionalArgsFunction(
			"(firstVersion, constraints ...string) bool",
			func(args ...interface{}) (interface{}, error) {
				if len(args) < 2 {
					return nil, ErrinvalidDslFunction
				}

				firstParsed, parseErr := version.NewVersion(toString(args[0]))
				if parseErr != nil {
					return nil, parseErr
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
			},
		),
		"print_debug": makeDslWithOptionalArgsFunction(
			"(args ...interface{})",
			func(args ...interface{}) (interface{}, error) {
				if len(args) < 1 {
					return nil, ErrinvalidDslFunction
				}
				if PrintDebugCallback != nil {
					if err := PrintDebugCallback(args...); err != nil {
						return nil, err
					}
				} else {
					gologger.Info().Msgf("print_debug value: %s", fmt.Sprint(args))
				}
				return true, nil
			},
		),
		"to_number": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			argStr := toString(args[0])
			if govalidator.IsInt(argStr) {
				sint, err := strconv.Atoi(argStr)
				return float64(sint), err
			} else if govalidator.IsFloat(argStr) {
				sint, err := strconv.ParseFloat(argStr, 64)
				return float64(sint), err
			}
			return nil, fmt.Errorf("%v could not be converted to int", argStr)
		}),
		"to_string": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return toString(args[0]), nil
		}),
		"dec_to_hex": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			if number, ok := args[0].(float64); ok {
				hexNum := strconv.FormatInt(int64(number), 16)
				return toString(hexNum), nil
			}
			return nil, fmt.Errorf("invalid number: %T", args[0])
		}),
		"hex_to_dec": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return stringNumberToDecimal(args, "0x", 16)
		}),
		"oct_to_dec": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return stringNumberToDecimal(args, "0o", 8)
		}),
		"bin_to_dec": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return stringNumberToDecimal(args, "0b", 2)
		}),
		"substr": makeDslWithOptionalArgsFunction(
			"(str string, start int, optionalEnd int)",
			func(args ...interface{}) (interface{}, error) {
				if len(args) < 2 {
					return nil, ErrinvalidDslFunction
				}
				argStr := toString(args[0])
				start, err := strconv.Atoi(toString(args[1]))
				if err != nil {
					return nil, errors.Wrap(err, "invalid start position")
				}
				if len(args) == 2 {
					return argStr[start:], nil
				}

				end, err := strconv.Atoi(toString(args[2]))
				if err != nil {
					return nil, errors.Wrap(err, "invalid end position")
				}
				if end < 0 {
					end += len(argStr)
				}
				return argStr[start:end], nil
			},
		),
		"aes_cbc": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
			bKey := []byte(args[1].(string))
			bIV := []byte(args[2].(string))
			bPlaintext := pkcs5padding([]byte(args[0].(string)), aes.BlockSize, len(args[0].(string)))
			block, _ := aes.NewCipher(bKey)
			ciphertext := make([]byte, len(bPlaintext))
			mode := cipher.NewCBCEncrypter(block, bIV)
			mode.CryptBlocks(ciphertext, bPlaintext)
			return ciphertext, nil
		}),
		"aes_gcm": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
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
			if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
				return "", err
			}
			data := gcm.Seal(nonce, nonce, []byte(value), nil)
			return data, nil
		}),
		"generate_jwt": makeDslWithOptionalArgsFunction(
			"(jsonString, optionalAlgorithm, optionalSignature string, optionalMaxAgeUnix interface{}) string",
			func(args ...interface{}) (interface{}, error) {
				var optionalAlgorithm string
				var optionalSignature []byte
				var optionalMaxAgeUnix time.Time

				var signOpts []jwt.SignOption
				var jsonData jwt.Map

				argSize := len(args)

				if argSize < 1 || argSize > 4 {
					return nil, ErrinvalidDslFunction
				}
				jsonString := args[0].(string)

				err := json.Unmarshal([]byte(jsonString), &jsonData)
				if err != nil {
					return nil, err
				}

				var algorithm jwt.Alg

				if argSize > 1 {
					alg := args[1].(string)
					optionalAlgorithm = strings.ToUpper(alg)

					switch optionalAlgorithm {
					case "":
						algorithm = jwt.NONE
					case "HS256":
						algorithm = jwt.HS256
					case "HS384":
						algorithm = jwt.HS384
					case "HS512":
						algorithm = jwt.HS512
					case "RS256":
						algorithm = jwt.RS256
					case "RS384":
						algorithm = jwt.RS384
					case "RS512":
						algorithm = jwt.RS512
					case "PS256":
						algorithm = jwt.PS256
					case "PS384":
						algorithm = jwt.PS384
					case "PS512":
						algorithm = jwt.PS512
					case "ES256":
						algorithm = jwt.ES256
					case "ES384":
						algorithm = jwt.ES384
					case "ES512":
						algorithm = jwt.ES512
					case "EDDSA":
						algorithm = jwt.EdDSA
					}

					if isjwtAlgorithmNone(alg) {
						algorithm = &algNONE{algValue: alg}
					}
					if algorithm == nil {
						return nil, fmt.Errorf("invalid algorithm: %s", optionalAlgorithm)
					}
				}

				if argSize > 2 {
					optionalSignature = []byte(args[2].(string))
				}

				if argSize > 3 {
					times := make([]interface{}, 2)
					times[0] = nil
					times[1] = args[3]

					optionalMaxAgeUnix, err = getCurrentTimeFromUserInput(times)
					if err != nil {
						return nil, err
					}

					duration := time.Until(optionalMaxAgeUnix)
					signOpts = append(signOpts, jwt.MaxAge(duration))
				}

				return jwt.Sign(algorithm, optionalSignature, jsonData, signOpts...)
			}),
		"json_minify": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
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
		}),
		"json_prettify": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			var buf bytes.Buffer

			err := json.Indent(&buf, []byte(args[0].(string)), "", "    ")
			if err != nil {
				return nil, err
			}

			return buf.String(), nil
		}),
		"ip_format": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
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
		}),
		"llm_prompt": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			prompt := args[0].(string)

			openaiToken := os.Getenv("OPENAI_TOKEN")

			if openaiToken == "" {
				return nil, errors.New("no token defined")
			}

			client := openai.NewClient(openaiToken)

			resp, err := client.CreateChatCompletion(
				context.Background(),
				openai.ChatCompletionRequest{
					Model: openai.GPT3Dot5Turbo,
					Messages: []openai.ChatCompletionMessage{
						{
							Role:    openai.ChatMessageRoleUser,
							Content: prompt,
						},
					},
				},
			)

			if err != nil {
				return nil, err
			}

			if len(resp.Choices) == 0 {
				return nil, errors.New("no data")
			}

			data := resp.Choices[0].Message.Content

			return data, nil
		}),
	}

	dslFunctions = make(map[string]dslFunction, len(tempDslFunctions))
	for funcName, dslFunc := range tempDslFunctions {
		dslFunctions[funcName] = dslFunc(funcName)
	}
	DefaultHelperFunctions = HelperFunctions()
	FunctionNames = GetFunctionNames(DefaultHelperFunctions)
}

func makeDslWithOptionalArgsFunction(signaturePart string, dslFunctionLogic govaluate.ExpressionFunction) func(functionName string) dslFunction {
	return makeMultiSignatureDslFunction([]string{signaturePart}, dslFunctionLogic)
}

func makeMultiSignatureDslFunction(signatureParts []string, dslFunctionLogic govaluate.ExpressionFunction) func(functionName string) dslFunction {
	return func(functionName string) dslFunction {
		methodSignatures := make([]string, 0, len(signatureParts))
		for _, signaturePart := range signatureParts {
			methodSignatures = append(methodSignatures, functionName+signaturePart)
		}

		return dslFunction{
			methodSignatures,
			dslFunctionLogic,
		}
	}
}

func makeDslFunction(numberOfParameters int, dslFunctionLogic govaluate.ExpressionFunction) func(functionName string) dslFunction {
	return func(functionName string) dslFunction {
		signature := functionName + createSignaturePart(numberOfParameters)
		return dslFunction{
			[]string{signature},
			func(args ...interface{}) (interface{}, error) {
				if len(args) != numberOfParameters {
					return nil, fmt.Errorf("%w. correct method signature %q", ErrinvalidDslFunction, signature)
				}
				return dslFunctionLogic(args...)
			},
		}
	}
}

func createSignaturePart(numberOfParameters int) string {
	params := make([]string, 0, numberOfParameters)
	for i := 1; i <= numberOfParameters; i++ {
		params = append(params, "arg"+strconv.Itoa(i))
	}
	return fmt.Sprintf("(%s interface{}) interface{}", strings.Join(params, ", "))
}

// HelperFunctions returns the dsl helper functions
func HelperFunctions() map[string]govaluate.ExpressionFunction {
	helperFunctions := make(map[string]govaluate.ExpressionFunction, len(dslFunctions))

	for functionName, dslFunction := range dslFunctions {
		helperFunctions[functionName] = dslFunction.expressFunc
		helperFunctions[strings.ReplaceAll(functionName, "_", "")] = dslFunction.expressFunc // for backwards compatibility
	}

	return helperFunctions
}

// AddMultiSignatureHelperFunction allows creation of additional helper functions to be supported with templates
func AddMultiSignatureHelperFunction(key string, signatureparts []string, value func(args ...interface{}) (interface{}, error)) error {
	if _, ok := dslFunctions[key]; !ok {
		dslFunction := dslFunctions[key]
		for i := range signatureparts {
			signatureparts[i] = key + signatureparts[i]
		}
		dslFunction.signatures = signatureparts
		dslFunction.expressFunc = value
		dslFunctions[key] = dslFunction
		return nil
	}
	return errors.New("duplicate helper function key defined")
}

func GetFunctionNames(heperFunctions map[string]govaluate.ExpressionFunction) []string {
	functionNames := make([]string, 0, len(heperFunctions))
	for k := range heperFunctions {
		functionNames = append(functionNames, k)
	}
	return functionNames
}

func GetPrintableDslFunctionSignatures(noColor bool) string {
	aggregateSignatures := func(values []string) string {
		sort.Strings(values)

		builder := &strings.Builder{}
		for _, value := range values {
			builder.WriteRune('\t')
			builder.WriteString(value)
			builder.WriteRune('\n')
		}
		return builder.String()
	}

	if noColor {
		return aggregateSignatures(getDslFunctionSignatures())
	}
	return aggregateSignatures(colorizeDslFunctionSignatures())
}

func getDslFunctionSignatures() []string {
	result := make([]string, 0, len(dslFunctions))

	for _, dslFunction := range dslFunctions {
		result = append(result, dslFunction.signatures...)
	}

	return result
}

func colorizeDslFunctionSignatures() []string {
	signatures := getDslFunctionSignatures()

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

func trimAll(s, cutset string) string {
	for _, c := range cutset {
		s = strings.ReplaceAll(s, string(c), "")
	}
	return s
}

func randSeq(base string, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = rune(base[rand.Intn(len(base))])
	}
	return string(b)
}

func toHexEncodedHash(hashToUse hash.Hash, data string) (interface{}, error) {
	if _, err := hashToUse.Write([]byte(data)); err != nil {
		return nil, err
	}
	return hex.EncodeToString(hashToUse.Sum(nil)), nil
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

func getCurrentTimeFromUserInput(arguments []interface{}) (time.Time, error) {
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
