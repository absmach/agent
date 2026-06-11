// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package encoder

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeSenML(t *testing.T) {
	tests := []struct {
		name   string
		bn     string
		n      string
		sv     string
		wantBn string
		wantN  string
		wantSv string
	}{
		{
			name:   "basic encoding",
			bn:     "req-1:",
			n:      "exec",
			sv:     "pwd",
			wantBn: "req-1:",
			wantN:  "exec",
			wantSv: "pwd",
		},
		{
			name:   "empty base name",
			bn:     "",
			n:      "response",
			sv:     "ok",
			wantBn: "",
			wantN:  "response",
			wantSv: "ok",
		},
		{
			name:   "multiline output",
			bn:     "req-2:",
			n:      "ls",
			sv:     "file1\nfile2\nfile3",
			wantBn: "req-2:",
			wantN:  "ls",
			wantSv: "file1\nfile2\nfile3",
		},
		{
			name:   "json in value",
			bn:     "req-3:",
			n:      "config",
			sv:     `{"key":"value"}`,
			wantBn: "req-3:",
			wantN:  "config",
			wantSv: `{"key":"value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := EncodeSenML(tt.bn, tt.n, tt.sv)
			require.NoError(t, err)

			var records []struct {
				BaseName    string  `json:"bn"`
				BaseTime    float64 `json:"bt"`
				Name        string  `json:"n"`
				StringValue *string `json:"vs"`
			}
			require.NoError(t, json.Unmarshal(payload, &records))
			require.Len(t, records, 1)

			rec := records[0]
			assert.Equal(t, tt.wantBn, rec.BaseName)
			assert.Equal(t, tt.wantN, rec.Name)
			require.NotNil(t, rec.StringValue)
			assert.Equal(t, tt.wantSv, *rec.StringValue)

			assert.Greater(t, rec.BaseTime, float64(1700000000), "bt should be in seconds, not nanoseconds")
			assert.Less(t, rec.BaseTime, float64(2000000000), "bt should be in seconds, not nanoseconds")
		})
	}
}
