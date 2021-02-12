package network

import (
	"net/url"

	"github.com/containers/podman/v2/pkg/bindings/util"
)

/*
This file is generated automatically by go generate.  Do not edit.
*/

// Changed
func (o *ConnectOptions) Changed(fieldName string) bool {
	return util.Changed(o, fieldName)
}

// ToParams
func (o *ConnectOptions) ToParams() (url.Values, error) {
	if o == nil {
		return url.Values{}, nil
	}
	return util.ToParams(o)
}

// WithAliases
func (o *ConnectOptions) WithAliases(value []string) *ConnectOptions {
	v := &value
	o.Aliases = v
	return o
}

// GetAliases
func (o *ConnectOptions) GetAliases() []string {
	var aliases []string
	if o.Aliases == nil {
		return aliases
	}
	return *o.Aliases
}
