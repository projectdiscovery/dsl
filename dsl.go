package dsl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"math"
	"math/rand"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/logrusorgru/aurora"
	"github.com/spaolacci/murmur3"
)

const (
	withCutSetArgsSize   = 2
	withMaxRandArgsSize  = withCutSetArgsSize
	withBaseRandArgsSize = 3
)

var letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
var numbers = "1234567890"
var functionSignaturePattern = regexp.MustCompile(`(\w+)\s*\((?:([\w\d,\s]+)\s+([.\w\d{}&*]+))?\)([\s.\w\d{}&*]+)?`)

var ErrInvalidDslFunction = errors.New("invalid DSL function signature")
var invalidDslFunctionMessageTemplate = "%w. correct method signature %q"

var dslFunctions map[string]dslFunction
var DefaultHelperFunctions map[string]govaluate.ExpressionFunction

type dslFunction struct {
	signature   string
	expressFunc govaluate.ExpressionFunction
}

// init initializes the dsl functions
func init() {
	tempDslFunctions := map[string]func(string) dslFunction{
		"len": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			length := len(toString(args[0]))
			return float64(length), nil
		}),
		"to_upper": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return strings.ToUpper(toString(args[0])), nil
		}),

		"to_lower": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return strings.ToLower(toString(args[0])), nil
		}),

		"replace": validateDsl(3, func(args ...interface{}) (interface{}, error) {
			return strings.ReplaceAll(toString(args[0]), toString(args[1]), toString(args[2])), nil
		}),

		"replace_regex": validateDsl(3, func(args ...interface{}) (interface{}, error) {
			compiled, err := Regex(toString(args[1]))
			if err != nil {
				return nil, err
			}
			return compiled.ReplaceAllString(toString(args[0]), toString(args[2])), nil
		}),

		"trim": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			return strings.Trim(toString(args[0]), toString(args[1])), nil
		}),

		"trim_left": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimLeft(toString(args[0]), toString(args[1])), nil
		}),

		"trim_right": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimRight(toString(args[0]), toString(args[1])), nil
		}),

		"trim_space": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return strings.TrimSpace(toString(args[0])), nil
		}),

		"trim_prefix": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimPrefix(toString(args[0]), toString(args[1])), nil
		}),

		"trim_suffix": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimSuffix(toString(args[0]), toString(args[1])), nil
		}),

		"reverse": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return reverseString(toString(args[0])), nil
		}),

		// encoding
		"base64": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			sEnc := base64.StdEncoding.EncodeToString([]byte(toString(args[0])))

			return sEnc, nil
		}),

		// python encodes to base64 with lines of 76 bytes terminated by new line "\n"
		"base64_py": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			sEnc := base64.StdEncoding.EncodeToString([]byte(toString(args[0])))

			return insertInto(sEnc, 76, '\n'), nil
		}),

		"base64_decode": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return base64.StdEncoding.DecodeString(toString(args[0]))
		}),

		"url_encode": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return url.PathEscape(toString(args[0])), nil
		}),

		"url_decode": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return url.PathUnescape(toString(args[0]))
		}),

		"hex_encode": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return hex.EncodeToString([]byte(toString(args[0]))), nil
		}),

		"hex_decode": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			hx, _ := hex.DecodeString(toString(args[0]))
			return string(hx), nil
		}),

		"html_escape": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return html.EscapeString(toString(args[0])), nil
		}),

		"html_unescape": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return html.UnescapeString(toString(args[0])), nil
		}),

		// hashing
		"md5": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			hash := md5.Sum([]byte(toString(args[0])))

			return hex.EncodeToString(hash[:]), nil
		}),

		"sha256": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			h := sha256.New()
			_, err := h.Write([]byte(toString(args[0])))

			if err != nil {
				return nil, err
			}

			return hex.EncodeToString(h.Sum(nil)), nil
		}),

		"sha1": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			h := sha1.New()
			_, err := h.Write([]byte(toString(args[0])))

			if err != nil {
				return nil, err
			}

			return hex.EncodeToString(h.Sum(nil)), nil
		}),

		"mmh3": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			return fmt.Sprintf("%d", int32(murmur3.Sum32WithSeed([]byte(toString(args[0])), 0))), nil
		}),

		// search
		"contains": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			return strings.Contains(toString(args[0]), toString(args[1])), nil
		}),

		"regex": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			compiled, err := Regex(toString(args[1]))
			if err != nil {
				return nil, err
			}

			return compiled.MatchString(toString(args[0])), nil
		}),

		"regex_all": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			for _, arg := range toSlice(args[1]) {
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

		"regex_any": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			for _, arg := range toSlice(args[1]) {
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

		"equals_any": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			for _, arg := range toSlice(args[1]) {
				if args[0] == arg {
					return true, nil
				}
			}
			return false, nil
		}),

		"contains_any": validateDsl(2, func(args ...interface{}) (interface{}, error) {

			for _, arg := range toSlice(args[1]) {
				if strings.Contains(toString(args[0]), toString(arg)) {
					return true, nil
				}
			}
			return false, nil
		}),

		"contains_all": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			for _, arg := range toSlice(args[1]) {
				if !strings.Contains(toString(args[0]), toString(arg)) {
					return false, nil
				}
			}
			return true, nil
		}),

		// random generators
		"rand_char": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			chars := letters + numbers
			bad := ""
			if len(args) >= 1 {
				chars = toString(args[0])
			}
			if len(args) >= withCutSetArgsSize {
				bad = toString(args[1])
			}

			chars = TrimAll(chars, bad)

			return chars[rand.Intn(len(chars))], nil
		}),

		"rand_base": validateDsl(3, func(args ...interface{}) (interface{}, error) {
			l := 0
			bad := ""
			base := letters + numbers

			if len(args) >= 1 {
				l = args[0].(int)
			}
			if len(args) >= withCutSetArgsSize {
				bad = toString(args[1])
			}
			if len(args) >= withBaseRandArgsSize {
				base = toString(args[2])
			}

			base = TrimAll(base, bad)

			return RandSeq(base, l), nil
		}),

		"rand_text_alphanumeric": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			l := 0
			bad := ""
			chars := letters + numbers

			if len(args) >= 1 {
				l = args[0].(int)
			}
			if len(args) >= withCutSetArgsSize {
				bad = toString(args[1])
			}

			chars = TrimAll(chars, bad)

			return RandSeq(chars, l), nil
		}),

		"rand_text_alpha": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			l := 0
			bad := ""
			chars := letters

			if len(args) >= 1 {
				l = args[0].(int)
			}
			if len(args) >= withCutSetArgsSize {
				bad = toString(args[1])
			}

			chars = TrimAll(chars, bad)

			return RandSeq(chars, l), nil
		}),

		"rand_text_numeric": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			l := 0
			bad := ""
			chars := numbers

			if len(args) >= 1 {
				l = args[0].(int)
			}
			if len(args) >= withCutSetArgsSize {
				bad = toString(args[1])
			}

			chars = TrimAll(chars, bad)

			return RandSeq(chars, l), nil
		}),

		"rand_int": validateDsl(2, func(args ...interface{}) (interface{}, error) {
			min := 0
			max := math.MaxInt32

			if len(args) >= 1 {
				min = args[0].(int)
			}
			if len(args) >= withMaxRandArgsSize {
				max = args[1].(int)
			}

			return rand.Intn(max-min) + min, nil
		}),

		// Time Functions
		"wait_for": validateDsl(1, func(args ...interface{}) (interface{}, error) {
			seconds := args[0].(float64)
			time.Sleep(time.Duration(seconds) * time.Second)
			return true, nil
		}),
	}

	dslFunctions = make(map[string]dslFunction, len(tempDslFunctions))
	for funcName, dslFunc := range tempDslFunctions {
		dslFunctions[funcName] = dslFunc(funcName)
	}
	DefaultHelperFunctions = helperFunctions()
}

// helperFunctions returns the dsl helper functions
func helperFunctions() map[string]govaluate.ExpressionFunction {
	helperFunctions := make(map[string]govaluate.ExpressionFunction, len(dslFunctions))

	for functionName, dslFunction := range dslFunctions {
		helperFunctions[functionName] = dslFunction.expressFunc
		helperFunctions[strings.ReplaceAll(functionName, "_", "")] = dslFunction.expressFunc // for backwards compatibility
	}

	return helperFunctions
}

func validateDsl(expectedArgsNumber int, dsl govaluate.ExpressionFunction) func(functionName string) dslFunction {
	return func(functionName string) dslFunction {
		signature := functionName + createSignaturePart(expectedArgsNumber)
		return dslFunction{
			signature,
			func(args ...interface{}) (interface{}, error) {
				if expectedArgsNumber != 0 && len(args) != expectedArgsNumber {
					return nil, fmt.Errorf(invalidDslFunctionMessageTemplate, ErrInvalidDslFunction, signature)

				}
				return dsl(args...)
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
		result = append(result, dslFunction.signature)
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
		subMatchSlices := functionSignaturePattern.FindAllStringSubmatch(signature, -1)
		if len(subMatchSlices) != 1 {
			// TODO log when nuclei#1166 is implemented
			return signatures
		}
		matches := subMatchSlices[0]
		if len(matches) != 5 {
			// TODO log when nuclei#1166 is implemented
			return signatures
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
