package util

import (
	"errors"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

func isSimpleType(f reflect.Value) bool {
	switch f.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int64, reflect.Uint, reflect.Uint64, reflect.String:
		return true
	}
	return false
}

func simpleTypeToParam(f reflect.Value) string {
	switch f.Kind() {
	case reflect.Bool:
		return strconv.FormatBool(f.Bool())
	case reflect.Int, reflect.Int64:
		// f.Int() is always an int64
		return strconv.FormatInt(f.Int(), 10)
	case reflect.Uint, reflect.Uint64:
		// f.Uint() is always an uint64
		return strconv.FormatUint(f.Uint(), 10)
	case reflect.String:
		return f.String()
	}
	panic("the input parameter is not a simple type")
}

func Changed(o interface{}, fieldName string) bool {
	r := reflect.ValueOf(o)
	value := reflect.Indirect(r).FieldByName(fieldName)
	return !value.IsNil()
}

func ToParams(o interface{}) (url.Values, error) {
	params := url.Values{}
	if o == nil {
		return params, nil
	}
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	s := reflect.ValueOf(o)
	if reflect.Ptr == s.Kind() {
		s = s.Elem()
	}
	sType := s.Type()
	for i := 0; i < s.NumField(); i++ {
		fieldName := sType.Field(i).Name
		if !Changed(o, fieldName) {
			continue
		}
		fieldName = strings.ToLower(fieldName)
		f := s.Field(i)
		if reflect.Ptr == f.Kind() {
			f = f.Elem()
		}
		switch {
		case isSimpleType(f):
			params.Set(fieldName, simpleTypeToParam(f))
		case f.Kind() == reflect.Slice:
			for i := 0; i < f.Len(); i++ {
				elem := f.Index(i)
				if isSimpleType(elem) {
					params.Add(fieldName, simpleTypeToParam(elem))
				} else {
					return nil, errors.New("slices must contain only simple types")
				}
			}
		case f.Kind() == reflect.Map:
			lowerCaseKeys := make(map[string][]string)
			iter := f.MapRange()
			for iter.Next() {
				lowerCaseKeys[iter.Key().Interface().(string)] = iter.Value().Interface().([]string)
			}
			s, err := json.MarshalToString(lowerCaseKeys)
			if err != nil {
				return nil, err
			}

			params.Set(fieldName, s)
		}
	}
	return params, nil
}
