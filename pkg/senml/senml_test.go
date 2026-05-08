// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package senml

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncode(t *testing.T) {
	cases := []struct {
		desc     string
		encode   func() ([]byte, error)
		response map[string]any
		absent   []string
		err      error
	}{
		{
			desc: "encode string successfully",
			encode: func() ([]byte, error) {
				return EncodeString("base:", "cmd", "hello")
			},
			response: map[string]any{
				"bn": "base:",
				"n":  "cmd",
				"vs": "hello",
			},
			absent: []string{"v"},
			err:    nil,
		},
		{
			desc: "encode float successfully",
			encode: func() ([]byte, error) {
				return EncodeFloat("gw:", "cpu_percent", 42.5, "%")
			},
			response: map[string]any{
				"v": 42.5,
				"u": "%",
			},
			absent: []string{"vs"},
			err:    nil,
		},
		{
			desc: "encode bool successfully",
			encode: func() ([]byte, error) {
				return EncodeBool("gw:", "online", true)
			},
			response: map[string]any{
				"vb": true,
			},
			err: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			payload, err := tc.encode()
			assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %v got %v", tc.desc, tc.err, err))
			if tc.err != nil {
				return
			}

			var records []map[string]any
			err = json.Unmarshal(payload, &records)
			assert.NoError(t, err, fmt.Sprintf("%s: unexpected error while unmarshalling payload: %s", tc.desc, err))
			if !assert.Len(t, records, 1, fmt.Sprintf("%s: unexpected records count", tc.desc)) {
				return
			}

			record := records[0]
			for key, value := range tc.response {
				assert.Equal(t, value, record[key], fmt.Sprintf("%s: unexpected %s", tc.desc, key))
			}
			for _, key := range tc.absent {
				assert.Nil(t, record[key], fmt.Sprintf("%s: expected %s to be absent", tc.desc, key))
			}
		})
	}
}

func TestDecode(t *testing.T) {
	encoded, err := EncodeString("uuid:", "control", "reboot")
	assert.NoError(t, err, fmt.Sprintf("unexpected error while encoding fixture: %s", err))

	cases := []struct {
		desc     string
		input    []byte
		response Record
		err      string
	}{
		{
			desc:  "decode payload successfully",
			input: encoded,
			response: Record{
				Name: "control",
			},
			err: "",
		},
		{
			desc:  "decode invalid json",
			input: []byte("not json"),
			err:   "senml decode",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			records, err := Decode(tc.input)
			if tc.err != "" {
				if !assert.Error(t, err, fmt.Sprintf("%s: expected error", tc.desc)) {
					return
				}
				assert.True(t, strings.Contains(err.Error(), tc.err), fmt.Sprintf("%s: expected error %q got %q", tc.desc, tc.err, err))
				return
			}

			assert.NoError(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
			if !assert.Len(t, records, 1, fmt.Sprintf("%s: unexpected records count", tc.desc)) {
				return
			}
			assert.Equal(t, tc.response.Name, records[0].Name, fmt.Sprintf("%s: unexpected name", tc.desc))
			if assert.NotNil(t, records[0].StringValue, fmt.Sprintf("%s: expected string value", tc.desc)) {
				assert.Equal(t, "reboot", *records[0].StringValue, fmt.Sprintf("%s: unexpected string value", tc.desc))
			}
		})
	}
}

func TestEncodeRecords(t *testing.T) {
	value1 := 1.0
	value2 := 2.0

	cases := []struct {
		desc     string
		records  []Record
		response int
		err      error
	}{
		{
			desc: "encode multiple records successfully",
			records: []Record{
				{BaseName: "gw:", Name: "cpu", Value: &value1},
				{Name: "mem", Value: &value2, Unit: "%"},
			},
			response: 2,
			err:      nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			payload, err := EncodeRecords(tc.records)
			assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %v got %v", tc.desc, tc.err, err))
			if tc.err != nil {
				return
			}

			var got []map[string]any
			err = json.Unmarshal(payload, &got)
			assert.NoError(t, err, fmt.Sprintf("%s: unexpected error while unmarshalling payload: %s", tc.desc, err))
			assert.Len(t, got, tc.response, fmt.Sprintf("%s: unexpected records count", tc.desc))
		})
	}
}
