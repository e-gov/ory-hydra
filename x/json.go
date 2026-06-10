// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package x

import (
	"database/sql/driver"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/ory/x/sqlxx"
)

// ConvertJSONNumbers walks a map and replaces each json.Number with an int64 when it
// fits, recursing into nested maps and slices. Values that do not fit an int64
// are converted to uint64 or float64 when possible, because go-jose renders
// json.Number as a quoted string.
func ConvertJSONNumbers(m map[string]any) {
	convertJSONNumber(m)
}

func convertJSONNumber(v any) any {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
		if u, err := strconv.ParseUint(n.String(), 10, 64); err == nil {
			return u
		}
		if f, err := n.Float64(); err == nil {
			return f
		}
		return n
	case map[string]any:
		for k, val := range n {
			n[k] = convertJSONNumber(val)
		}
		return n
	case []any:
		for i, val := range n {
			n[i] = convertJSONNumber(val)
		}
		return n
	default:
		return v
	}
}

// MapStringInterface is a map[string]any that works with SQL and JSON
// while preserving integer precision. Unlike sqlxx.MapStringInterface, its Scan
// decodes with json.Decoder.UseNumber and then coerces numbers via
// ConvertJSONNumbers, so integer claims survive a database round-trip as int64
// (or uint64 beyond int64) instead of being collapsed to float64 and later
// re-serialized by go-jose in scientific notation.
type MapStringInterface map[string]any

// Scan implements the sql.Scanner interface.
func (n *MapStringInterface) Scan(value any) error {
	var v string
	switch raw := value.(type) {
	case nil:
		return nil
	case string:
		v = raw
	case []byte:
		v = string(raw)
	default:
		return errors.Errorf("unsupported type %T for MapStringInterface.Scan", value)
	}
	if len(v) == 0 {
		return nil
	}

	dec := json.NewDecoder(strings.NewReader(v))
	dec.UseNumber()
	if err := dec.Decode((*map[string]any)(n)); err != nil {
		return errors.WithStack(err)
	}
	ConvertJSONNumbers(*n)
	return nil
}

func (n MapStringInterface) Value() (driver.Value, error) {
	return sqlxx.MapStringInterface(n).Value()
}
