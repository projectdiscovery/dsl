package testing

import (
	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/dsl"
	"testing"
)

var data = map[string]interface{}{
	"username": "johndoe",
	"email":    "johndoe@example.com",
	"password": "12345",
	"ip":       "127.0.0.1",
	"url":      "https://www.example.com",
	"date":     "2022-05-01",
}

func Helper(expressions map[string]string, t *testing.T) {
	for matcherName, expression := range expressions {
		compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(expression, dsl.DefaultHelperFunctions)
		if err != nil {
			t.Logf("Failed to compile expresion: %v\n", expression)
		}

		result, err := compiledExpression.Evaluate(data)
		if err != nil {
			t.Logf("Failed to evaluate expresion: %v\n", expression)
		}

		if result == true {
			t.Logf("[%v] matches data\n", matcherName)
		} else {
			t.Logf("[%v] not matches data\n", matcherName)
		}
	}
}

func TestSliceOps(t *testing.T) {
	// Define the expressions to evaluate
	expressions := map[string]string{
		"split-01": "index(split(url, '.', -1), 1) == 'example'",
		// "sprintf-01": "(split(url,'.',-1))[1] == 'example' ",
		"split-02":   "len(split(url, '.', -1)) == 3",
		"sprintf-02": "print_debug(split(\"https://www.example.com\", \".\", -1))",
		"split-04":   "len(url) == 23",
		"test":       "index(url, 1) == 't'",
	}
	Helper(expressions, t)
}
