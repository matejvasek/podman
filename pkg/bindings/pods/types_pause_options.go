package pods

import (
	"net/url"

	"github.com/containers/podman/v2/pkg/bindings/util"
)

/*
This file is generated automatically by go generate.  Do not edit.
*/

// Changed
func (o *PauseOptions) Changed(fieldName string) bool {
	return util.Changed(o, fieldName)
}

// ToParams
func (o *PauseOptions) ToParams() (url.Values, error) {
	if o == nil {
		return url.Values{}, nil
	}
	return util.ToParams(o)
}
