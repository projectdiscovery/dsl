package dsl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Knetic/govaluate"
)

type dslFunction struct {
	name               string
	numberOfArgs       int
	signatures         []string
	expressionFunction govaluate.ExpressionFunction
}

func (d dslFunction) Signatures() []string {
	// fixed number of args
	if d.numberOfArgs > 0 {
		args := make([]string, 0, d.numberOfArgs)
		for i := 1; i <= d.numberOfArgs; i++ {
			args = append(args, "arg"+strconv.Itoa(i))
		}
		argsPart := fmt.Sprintf("(%s interface{}) interface{}", strings.Join(args, ", "))
		signature := d.name + argsPart
		return []string{signature}
	}

	// multi signatures
	var signatures []string
	for _, signature := range d.signatures {
		signatures = append(signatures, d.name+signature)
	}

	return signatures
}

func (d dslFunction) Exec(args ...interface{}) (interface{}, error) {
	if d.numberOfArgs > 0 {
		if len(args) != d.numberOfArgs {
			signatures := d.Signatures()
			if len(signatures) > 0 {
				return nil, fmt.Errorf("%w. correct method signature %q", ErrinvalidDslFunction, signatures[0])
			}
			return nil, ErrinvalidDslFunction
		}
	}

	return d.expressionFunction(args...)
}
