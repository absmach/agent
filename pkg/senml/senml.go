// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package senml

import (
	"fmt"
	"time"

	"github.com/absmach/senml"
)

// Record is a re-export so callers don't need to import the upstream package.
type Record = senml.Record

// Pack is a re-export so callers don't need to import the upstream package.
type Pack = senml.Pack

func now() float64 {
	return float64(time.Now().UnixNano()) / float64(time.Second)
}

func pack(bn, n string, r senml.Record) ([]byte, error) {
	r.BaseName = bn
	r.Name = n
	r.Time = now()
	return encode(senml.Pack{Records: []senml.Record{r}})
}

func encode(p senml.Pack) ([]byte, error) {
	b, err := senml.Encode(p, senml.JSON)
	if err != nil {
		return nil, fmt.Errorf("senml encode: %w", err)
	}
	return b, nil
}

// EncodeString encodes a single string-valued record.
func EncodeString(bn, n, v string) ([]byte, error) {
	return pack(bn, n, senml.Record{StringValue: &v})
}

// EncodeFloat encodes a single numeric record with optional unit.
func EncodeFloat(bn, n string, v float64, unit string) ([]byte, error) {
	return pack(bn, n, senml.Record{Value: &v, Unit: unit})
}

// EncodeBool encodes a single boolean record.
func EncodeBool(bn, n string, v bool) ([]byte, error) {
	return pack(bn, n, senml.Record{BoolValue: &v})
}

// EncodeRecords encodes an arbitrary slice of records as a SenML JSON array.
func EncodeRecords(records []senml.Record) ([]byte, error) {
	return encode(senml.Pack{Records: records})
}

// Decode parses a SenML JSON payload into a slice of records.
func Decode(data []byte) ([]senml.Record, error) {
	p, err := senml.Decode(data, senml.JSON)
	if err != nil {
		return nil, fmt.Errorf("senml decode: %w", err)
	}
	return p.Records, nil
}
