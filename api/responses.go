// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/health"
	"github.com/absmach/magistrala"
)

var (
	_ magistrala.Response = (*publishRes)(nil)
	_ magistrala.Response = (*execRes)(nil)
	_ magistrala.Response = (*healthRes)(nil)
	_ magistrala.Response = (*addConfigRes)(nil)
	_ magistrala.Response = (*viewConfigRes)(nil)
	_ magistrala.Response = (*viewServicesRes)(nil)
	_ magistrala.Response = (*nodeRedRes)(nil)
)

type publishRes struct {
	Service  string `json:"service"`
	Response string `json:"response"`
}

func (res publishRes) Code() int {
	return http.StatusOK
}

func (res publishRes) Headers() map[string]string {
	return map[string]string{}
}

func (res publishRes) Empty() bool {
	return false
}

type execRes struct {
	BaseName string `json:"bn"`
	Name     string `json:"n"`
	Value    string `json:"vs"`
}

func (res execRes) Code() int {
	return http.StatusOK
}

func (res execRes) Headers() map[string]string {
	return map[string]string{}
}

func (res execRes) Empty() bool {
	return false
}

type addConfigRes struct {
	Service  string `json:"service"`
	Response string `json:"response"`
}

func (res addConfigRes) Code() int {
	return http.StatusOK
}

func (res addConfigRes) Headers() map[string]string {
	return map[string]string{}
}

func (res addConfigRes) Empty() bool {
	return false
}

type viewConfigRes struct {
	agent.Config
}

func (res viewConfigRes) Code() int {
	return http.StatusOK
}

func (res viewConfigRes) Headers() map[string]string {
	return map[string]string{}
}

func (res viewConfigRes) Empty() bool {
	return false
}

type viewServicesRes []agent.Info

func (res viewServicesRes) Code() int {
	return http.StatusOK
}

func (res viewServicesRes) Headers() map[string]string {
	return map[string]string{}
}

func (res viewServicesRes) Empty() bool {
	return false
}

type nodeRedRes struct {
	Service  string `json:"service"`
	Response string `json:"response"`
}

func (res nodeRedRes) Code() int {
	return http.StatusOK
}

func (res nodeRedRes) Headers() map[string]string {
	return map[string]string{}
}

func (res nodeRedRes) Empty() bool {
	return false
}

type healthRes struct {
	*health.Metrics
}

func (res healthRes) Code() int {
	if res.Metrics == nil {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func (res healthRes) Headers() map[string]string {
	return map[string]string{}
}

func (res healthRes) Empty() bool {
	return res.Metrics == nil
}
