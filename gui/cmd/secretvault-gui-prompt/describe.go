package main

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// fact is one "Name: value" line at the end of a description. It is how
// secretvaultd names the program that is asking ("Program: /usr/bin/mail",
// "Process: 4242"), and the dialog sets them out as a small table so the
// program is the first thing read, not the last.
type fact struct{ name, value string }

// splitDescription cuts a pinentry description into paragraphs of lines,
// and, where its last paragraph is nothing but "Name: value" lines, takes
// that one as facts instead.
func splitDescription(desc string) (paras [][]string, facts []fact) {
	desc = strings.ReplaceAll(desc, "\r\n", "\n")
	for _, p := range strings.Split(desc, "\n\n") {
		var lines []string
		for _, l := range strings.Split(p, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
		if len(lines) > 0 {
			paras = append(paras, lines)
		}
	}
	n := len(paras)
	if n == 0 {
		return nil, nil
	}
	for _, l := range paras[n-1] {
		f, ok := factLine(l)
		if !ok {
			return paras, nil
		}
		facts = append(facts, f)
	}
	return paras[:n-1], facts
}

// factLine reads "Name: value", where the name is a word or three that
// starts with a capital: short enough to be a label and not a sentence
// that happens to hold a colon.
func factLine(l string) (fact, bool) {
	name, value, ok := strings.Cut(l, ": ")
	value = strings.TrimSpace(value)
	if !ok || value == "" || len(name) > 24 {
		return fact{}, false
	}
	first, _ := utf8.DecodeRuneInString(name)
	if !unicode.IsUpper(first) || strings.Count(name, " ") > 2 {
		return fact{}, false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && r != ' ' {
			return fact{}, false
		}
	}
	return fact{name, value}, true
}
