// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package senml

import (
	"encoding/json"
	"testing"
)

func TestEncodeString(t *testing.T) {
	b, err := EncodeString("base:", "cmd", "hello")
	if err != nil {
		t.Fatalf("EncodeString error: %v", err)
	}

	var records []map[string]any
	if err := json.Unmarshal(b, &records); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r["bn"] != "base:" {
		t.Errorf("bn: want %q got %v", "base:", r["bn"])
	}
	if r["n"] != "cmd" {
		t.Errorf("n: want %q got %v", "cmd", r["n"])
	}
	if r["vs"] != "hello" {
		t.Errorf("vs: want %q got %v", "hello", r["vs"])
	}
	if r["v"] != nil {
		t.Errorf("v should be absent for string record, got %v", r["v"])
	}
}

func TestEncodeFloat(t *testing.T) {
	b, err := EncodeFloat("gw:", "cpu_percent", 42.5, "%")
	if err != nil {
		t.Fatalf("EncodeFloat error: %v", err)
	}

	var records []map[string]any
	if err := json.Unmarshal(b, &records); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	r := records[0]
	if r["v"] != 42.5 {
		t.Errorf("v: want 42.5 got %v", r["v"])
	}
	if r["u"] != "%" {
		t.Errorf("u: want %% got %v", r["u"])
	}
	if r["vs"] != nil {
		t.Errorf("vs should be absent for numeric record, got %v", r["vs"])
	}
}

func TestEncodeBool(t *testing.T) {
	b, err := EncodeBool("gw:", "online", true)
	if err != nil {
		t.Fatalf("EncodeBool error: %v", err)
	}

	var records []map[string]any
	if err := json.Unmarshal(b, &records); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	r := records[0]
	if r["vb"] != true {
		t.Errorf("vb: want true got %v", r["vb"])
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	encoded, err := EncodeString("uuid:", "control", "reboot")
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	records, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.Name != "control" {
		t.Errorf("Name: want %q got %q", "control", r.Name)
	}
	if r.StringValue == nil || *r.StringValue != "reboot" {
		t.Errorf("StringValue: want %q got %v", "reboot", r.StringValue)
	}
}

func TestDecodeInvalidJSON(t *testing.T) {
	_, err := Decode([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestEncodeRecordsMultiple(t *testing.T) {
	v1 := 1.0
	v2 := 2.0
	records := []Record{
		{BaseName: "gw:", Name: "cpu", Value: &v1},
		{Name: "mem", Value: &v2, Unit: "%"},
	}

	b, err := EncodeRecords(records)
	if err != nil {
		t.Fatalf("EncodeRecords error: %v", err)
	}

	var got []map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 records, got %d", len(got))
	}
}
