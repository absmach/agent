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
	_ magistrala.Response = (*execRes)(nil)
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

type listDevicesRes struct {
	Devices []devicemgr.Device `json:"devices"`
}

func (res listDevicesRes) Code() int            { return http.StatusOK }
func (res listDevicesRes) Headers() map[string]string { return map[string]string{} }
func (res listDevicesRes) Empty() bool          { return false }

type getDeviceRes struct {
	devicemgr.Device
}

func (res getDeviceRes) Code() int            { return http.StatusOK }
func (res getDeviceRes) Headers() map[string]string { return map[string]string{} }
func (res getDeviceRes) Empty() bool          { return false }

type addDeviceRes struct {
	devicemgr.Device
}

func (res addDeviceRes) Code() int            { return http.StatusCreated }
func (res addDeviceRes) Headers() map[string]string { return map[string]string{} }
func (res addDeviceRes) Empty() bool          { return false }

type removeDeviceRes struct{}

func (res removeDeviceRes) Code() int            { return http.StatusNoContent }
func (res removeDeviceRes) Headers() map[string]string { return map[string]string{} }
func (res removeDeviceRes) Empty() bool          { return true }

type markDeviceSeenRes struct{}

func (res markDeviceSeenRes) Code() int            { return http.StatusNoContent }
func (res markDeviceSeenRes) Headers() map[string]string { return map[string]string{} }
func (res markDeviceSeenRes) Empty() bool          { return true }

type otaTriggerRes struct {
	Status string `json:"status"`
}

func (res otaTriggerRes) Code() int            { return http.StatusAccepted }
func (res otaTriggerRes) Headers() map[string]string { return map[string]string{} }
func (res otaTriggerRes) Empty() bool          { return false }

type otaStatusRes struct {
	agent.OTAStatusInfo
}

func (res otaStatusRes) Code() int            { return http.StatusOK }
func (res otaStatusRes) Headers() map[string]string { return map[string]string{} }
func (res otaStatusRes) Empty() bool          { return false }
