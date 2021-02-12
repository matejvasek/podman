package containers

import (
	"net/url"

	"github.com/containers/podman/v2/pkg/bindings/util"
)

/*
This file is generated automatically by go generate.  Do not edit.
*/

// Changed
func (o *KillOptions) Changed(fieldName string) bool {
	return util.Changed(o, fieldName)
}

// ToParams
func (o *KillOptions) ToParams() (url.Values, error) {
	if o == nil {
		return url.Values{}, nil
	}
	return util.ToParams(o)
}

// WithSignal
func (o *KillOptions) WithSignal(value string) *KillOptions {
	v := &value
	o.Signal = v
	return o
}

// GetSignal
func (o *KillOptions) GetSignal() string {
	var signal string
	if o.Signal == nil {
		return signal
	}
	return *o.Signal
}
