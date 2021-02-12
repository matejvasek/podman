package containers

import (
	"net/url"

	"github.com/containers/podman/v2/pkg/bindings/util"
)

/*
This file is generated automatically by go generate.  Do not edit.
*/

// Changed
func (o *ShouldRestartOptions) Changed(fieldName string) bool {
	return util.Changed(o, fieldName)
}

// ToParams
func (o *ShouldRestartOptions) ToParams() (url.Values, error) {
	if o == nil {
		return url.Values{}, nil
	}
	return util.ToParams(o)
}
