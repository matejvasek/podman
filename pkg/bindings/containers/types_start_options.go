package containers

import (
	"net/url"

	"github.com/containers/podman/v2/pkg/bindings/util"
)

/*
This file is generated automatically by go generate.  Do not edit.
*/

// Changed
func (o *StartOptions) Changed(fieldName string) bool {
	return util.Changed(o, fieldName)
}

// ToParams
func (o *StartOptions) ToParams() (url.Values, error) {
	if o == nil {
		return url.Values{}, nil
	}
	return util.ToParams(o)
}

// WithDetachKeys
func (o *StartOptions) WithDetachKeys(value string) *StartOptions {
	v := &value
	o.DetachKeys = v
	return o
}

// GetDetachKeys
func (o *StartOptions) GetDetachKeys() string {
	var detachKeys string
	if o.DetachKeys == nil {
		return detachKeys
	}
	return *o.DetachKeys
}
