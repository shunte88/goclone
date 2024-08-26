package cmd

// Package implements parser of cookies txt format that
// commonly supported by command line utilities
// curl, wget, aria2c
// as well as chrome, firefox, edge and others
//

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// enum "fields"
const (
	// The host/domain that created AND that can read the variable.
	domainIdx = iota
	// The path within the domain that the variable is valid for.
	pathIdx = iota + 1
	// A TRUE/FALSE value indicating if a secure connection with the domain is needed to access the variable.
	secureIdx
	// The UNIX time that the variable will expire on. UNIX time is defined as the number of seconds since Jan 1, 1970 00:00:00 GMT.
	expirationIdx
	// The name of the variable.
	nameIdx
	// The value of the variable.
	valueIdx
)

const (
	httpOnlyPrefix = "#HttpOnly_"
	fieldsCount    = 7
)

// Parse cookie txt file format from input stream
func Parse(rd io.Reader) (cl []*http.Cookie, err error) {
	scanner := bufio.NewScanner(rd)
	var line int
	for scanner.Scan() {
		line++

		trimed := strings.TrimSpace(scanner.Text())
		if len(trimed) < fieldsCount {
			continue
		}

		if trimed[0] == '#' && !strings.HasPrefix(trimed, httpOnlyPrefix) {
			// comment
			continue
		}

		var c *http.Cookie
		c, err = ParseLine(scanner.Text())
		if err != nil {
			return cl, fmt.Errorf("cookiestxt line:%d, err:%s", line, err)
		}
		cl = append(cl, c)
		line++
	}

	err = scanner.Err()
	return
}

// ParseLine parse single cookie from one line
func ParseLine(raw string) (c *http.Cookie, err error) {
	f := strings.Fields(raw)
	if len(f) == fieldsCount-1 {
		f = append(f, "")
	} else if len(f) < fieldsCount {
		err = fmt.Errorf("expecting fields=7, got=%d", len(f))
		return
	}

	c = &http.Cookie{
		Raw:    raw,
		Name:   f[nameIdx],
		Value:  f[valueIdx],
		Path:   f[pathIdx],
		MaxAge: 0,
		Secure: parseBool(f[secureIdx]),
	}

	var ts int64
	ts, err = strconv.ParseInt(f[expirationIdx], 10, 64)
	if err != nil {
		return
	}
	c.Expires = time.Unix(ts, 0)

	c.Domain = f[domainIdx]
	if strings.HasPrefix(c.Domain, httpOnlyPrefix) {
		c.HttpOnly = true
		c.Domain = c.Domain[len(httpOnlyPrefix):]
	}

	return
}

func parseBool(input string) bool {
	return strings.ToUpper(input) == "TRUE"
}
