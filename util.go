package dsl

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
)

func toString(v interface{}) string {
	return fmt.Sprint(v)
}

func toSlice(v interface{}) (m []string) {
	switch v.(type) {
	case []string:
		for _, item := range v.([]string) {
			m = append(m, toString(item))
		}
	case []int:
		for _, item := range v.([]int) {
			m = append(m, toString(item))
		}
	case []float64:
		for _, item := range v.([]float64) {
			m = append(m, toString(item))
		}
	}
	return
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
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
		b[i] = rune(base[rand.Intn(len(base))])
	}
	return string(b)
}
