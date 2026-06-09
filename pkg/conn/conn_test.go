// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package conn

import (
	"testing"

	"github.com/absmach/agent/pkg/senml"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeCommand(t *testing.T) {
	token := "my-secret-token"
	validRecord := senml.Record{Name: "token", StringValue: &token}
	otherRecord := senml.Record{Name: "config", StringValue: new("get,log_level")}

	cases := []struct {
		desc    string
		records []senml.Record
		secret  string
		want    bool
	}{
		{
			desc:    "valid token matches secret",
			records: []senml.Record{otherRecord, validRecord},
			secret:  "my-secret-token",
			want:    true,
		},
		{
			desc:    "invalid token does not match",
			records: []senml.Record{otherRecord, {Name: "token", StringValue: new("wrong-token")}},
			secret:  "my-secret-token",
			want:    false,
		},
		{
			desc:    "missing token record returns false",
			records: []senml.Record{otherRecord},
			secret:  "my-secret-token",
			want:    false,
		},
		{
			desc:    "token record with nil string value returns false",
			records: []senml.Record{otherRecord, {Name: "token"}},
			secret:  "my-secret-token",
			want:    false,
		},
		{
			desc:    "empty secret matches empty token",
			records: []senml.Record{otherRecord, {Name: "token", StringValue: new("")}},
			secret:  "",
			want:    true,
		},
		{
			desc:    "empty token does not match non-empty secret",
			records: []senml.Record{otherRecord, {Name: "token", StringValue: new("")}},
			secret:  "my-secret-token",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := authorizeCommand(tc.records, tc.secret)
			assert.Equal(t, tc.want, got)
		})
	}
}
