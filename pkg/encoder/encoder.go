// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package encoder

import (
	"time"

	"github.com/absmach/senml"
)

func EncodeSenML(bn, n, sv string) ([]byte, error) {
	now := float64(time.Now().UnixNano())
	s := senml.Pack{
		Records: []senml.Record{
			{
				BaseName:    bn,
				BaseTime:    now,
				Name:        n,
				StringValue: &sv,
			},
		},
	}
	payload, err := senml.Encode(s, senml.JSON)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
