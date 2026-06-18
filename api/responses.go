// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/absmach/agent"
	"github.com/absmach/agent/pkg/devicemgr"
	"github.com/absmach/magistrala"
)

var (
	_ magistrala.Response = (*publishRes)(nil)
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

type listDevicesRes struct {
	Devices []devicemgr.Device `json:"devices"`
}

func (res listDevicesRes) Code() int {
	return http.StatusOK
}

func (res listDevicesRes) Headers() map[string]string {
	return map[string]string{}
}

func (res listDevicesRes) Empty() bool {
	return false
}

type getDeviceRes struct {
	devicemgr.Device
}

func (res getDeviceRes) Code() int {
	return http.StatusOK
}

func (res getDeviceRes) Headers() map[string]string {
	return map[string]string{}
}

func (res getDeviceRes) Empty() bool {
	return false
}

type addDeviceRes struct {
	devicemgr.Device
}

func (res addDeviceRes) Code() int {
	return http.StatusCreated
}

func (res addDeviceRes) Headers() map[string]string {
	return map[string]string{"Location": "/devices/" + res.ID}
}

func (res addDeviceRes) Empty() bool {
	return false
}

type removeDeviceRes struct{}

func (res removeDeviceRes) Code() int {
	return http.StatusNoContent
}

func (res removeDeviceRes) Headers() map[string]string {
	return map[string]string{}
}

func (res removeDeviceRes) Empty() bool {
	return true
}

type markDeviceSeenRes struct{}

func (res markDeviceSeenRes) Code() int {
	return http.StatusNoContent
}

func (res markDeviceSeenRes) Headers() map[string]string {
	return map[string]string{}
}

func (res markDeviceSeenRes) Empty() bool {
	return true
}

type resetRes struct {
	Service  string `json:"service"`
	Response string `json:"response"`
	Mode     string `json:"mode"`
}

func (res resetRes) Code() int {
	return http.StatusAccepted
}

func (res resetRes) Headers() map[string]string {
	return map[string]string{}
}

func (res resetRes) Empty() bool {
	return false
}

type otaTriggerRes struct {
	Status string `json:"status"`
}

func (res otaTriggerRes) Code() int {
	return http.StatusAccepted
}

func (res otaTriggerRes) Headers() map[string]string {
	return map[string]string{}
}

func (res otaTriggerRes) Empty() bool {
	return false
}

type otaStatusRes struct {
	agent.OTAStatusInfo
}

func (res otaStatusRes) Code() int {
	return http.StatusOK
}

func (res otaStatusRes) Headers() map[string]string {
	return map[string]string{}
}

func (res otaStatusRes) Empty() bool {
	return false
}

type simpleRes struct {
	Service  string `json:"service"`
	Response string `json:"response"`
}

func (res simpleRes) Code() int {
	return http.StatusOK
}

func (res simpleRes) Headers() map[string]string {
	return map[string]string{}
}

func (res simpleRes) Empty() bool {
	return false
}

type runtimeConfigRes struct {
	Config map[string]string `json:"config"`
}

func (res runtimeConfigRes) Code() int {
	return http.StatusOK
}

func (res runtimeConfigRes) Headers() map[string]string {
	return map[string]string{}
}

func (res runtimeConfigRes) Empty() bool {
	return false
}

type deviceReadRes struct {
	Data string `json:"data"`
}

func (res deviceReadRes) Code() int {
	return http.StatusOK
}

func (res deviceReadRes) Headers() map[string]string {
	return map[string]string{}
}

func (res deviceReadRes) Empty() bool {
	return false
}

type deviceWriteRes struct {
	Bytes int `json:"bytes"`
}

func (res deviceWriteRes) Code() int {
	return http.StatusOK
}

func (res deviceWriteRes) Headers() map[string]string {
	return map[string]string{}
}

func (res deviceWriteRes) Empty() bool {
	return false
}

type terminalRes struct {
	SessionID string `json:"session_id"`
}

func (res terminalRes) Code() int {
	return http.StatusOK
}

func (res terminalRes) Headers() map[string]string {
	return map[string]string{}
}

func (res terminalRes) Empty() bool {
	return false
}
