/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"regexp"
	"strings"

	"github.com/gravitational/trace"
)

// GlobToRegexp replaces glob-style standalone wildcard values
// with real .* regexp-friendly values, does not modify regexp-compatible values,
// quotes non-wildcard values
func GlobToRegexp(in string) string {
	return replaceWildcard.ReplaceAllString(regexp.QuoteMeta(in), "(.*)")
}

// ReplaceRegexp replaces value in string, accepts regular expression and simplified
// wildcard syntax, it has several important differeneces with standard lib
// regexp replacer:
// * Wildcard globs '*' are treated as regular expression .* expression
// * Expression is treated as regular expression if it starts with ^ and ends with $
// * Full match is expected, partial replacements ignored
// * If there is no match, returns not found error
func ReplaceRegexp(expression string, replaceWith string, input string) (string, error) {
	if !strings.HasPrefix(expression, "^") || !strings.HasSuffix(expression, "$") {
		// replace glob-style wildcards with regexp wildcards
		// for plain strings, and quote all characters that could
		// be interpreted in regular expression
		expression = "^" + GlobToRegexp(expression) + "$"
	}
	expr, err := regexp.Compile(expression)
	if err != nil {
		return "", trace.BadParameter(err.Error())
	}
	// if there is no match, return NotFound error
	index := expr.FindAllStringIndex(input, -1)
	if len(index) == 0 {
		return "", trace.NotFound("no match found")
	}
	return expr.ReplaceAllString(input, replaceWith), nil
}

var replaceWildcard = regexp.MustCompile(`(\\\*)`)