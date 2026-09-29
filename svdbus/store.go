package svdbus

import (
	"fmt"
	"math"
	"reflect"
)

// Store copies decoded values into typed Go values, one pointer per value,
// as encoding/json's Unmarshal fills a struct:
//
//   - a value whose type is assignable to the target is taken as it is;
//   - a Variant target takes any value (wrapping it), and a Variant source
//     is unwrapped into any other target;
//   - integers go into any integer kind they fit, floats into float kinds,
//     strings, object paths and signatures into any string kind;
//   - slices and arrays element by element, maps key and value by key and
//     value, structs field by field (exported fields, in order) from []any;
//   - pointers are allocated as needed;
//   - UnixFD goes only into UnixFD (or an interface), never into an integer.
//
// Anything else is an error wrapping ErrInvalid.
func Store(src []any, dst ...any) error {
	if len(src) != len(dst) {
		return invalidf("%d values to store in %d destinations", len(src), len(dst))
	}
	for i, d := range dst {
		rv := reflect.ValueOf(d)
		if rv.Kind() != reflect.Pointer || rv.IsNil() {
			return invalidf("destination %d is %T, not a non-nil pointer", i, d)
		}
		if err := store(rv.Elem(), src[i], 0); err != nil {
			return fmt.Errorf("value %d: %w", i, err)
		}
	}
	return nil
}

func storeMismatch(src any, dst reflect.Type) error {
	return invalidf("cannot store %T in %s", src, dst)
}

func store(dst reflect.Value, src any, depth int) error {
	if depth > 2*MaxDepth {
		return invalidf("value nests too deeply to store")
	}
	dt := dst.Type()
	if src == nil {
		switch dt.Kind() {
		case reflect.Interface, reflect.Pointer, reflect.Slice, reflect.Map:
			dst.Set(reflect.Zero(dt))
			return nil
		}
		return storeMismatch(src, dt)
	}
	sv := reflect.ValueOf(src)
	if sv.Type().AssignableTo(dt) {
		dst.Set(sv)
		return nil
	}
	if dt == variantType {
		dst.Set(reflect.ValueOf(MakeVariant(src)))
		return nil
	}
	if v, ok := src.(Variant); ok {
		return store(dst, v.Value, depth+1)
	}
	if dt == unixFDType || sv.Type() == unixFDType {
		return storeMismatch(src, dt)
	}
	switch dt.Kind() {
	case reflect.Pointer:
		if dst.IsNil() {
			dst.Set(reflect.New(dt.Elem()))
		}
		return store(dst.Elem(), src, depth+1)
	case reflect.Bool:
		if sv.Kind() != reflect.Bool {
			return storeMismatch(src, dt)
		}
		dst.SetBool(sv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bits := dt.Bits()
		n, ok := intOf(sv, -1<<(bits-1), 1<<(bits-1)-1)
		if !ok {
			return storeMismatch(src, dt)
		}
		dst.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		n, ok := uintOf(sv, math.MaxUint64>>(64-dt.Bits()))
		if !ok {
			return storeMismatch(src, dt)
		}
		dst.SetUint(n)
	case reflect.Float32, reflect.Float64:
		if sv.Kind() != reflect.Float64 && sv.Kind() != reflect.Float32 {
			return storeMismatch(src, dt)
		}
		dst.SetFloat(sv.Float())
	case reflect.String:
		if sv.Kind() != reflect.String {
			return storeMismatch(src, dt)
		}
		dst.SetString(sv.String())
	case reflect.Slice:
		if sv.Kind() != reflect.Slice && sv.Kind() != reflect.Array {
			return storeMismatch(src, dt)
		}
		n := sv.Len()
		out := reflect.MakeSlice(dt, n, n)
		for i := 0; i < n; i++ {
			if err := store(out.Index(i), sv.Index(i).Interface(), depth+1); err != nil {
				return err
			}
		}
		dst.Set(out)
	case reflect.Array:
		if sv.Kind() != reflect.Slice && sv.Kind() != reflect.Array || sv.Len() != dt.Len() {
			return storeMismatch(src, dt)
		}
		for i := 0; i < dt.Len(); i++ {
			if err := store(dst.Index(i), sv.Index(i).Interface(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		if sv.Kind() != reflect.Map {
			return storeMismatch(src, dt)
		}
		out := reflect.MakeMapWithSize(dt, sv.Len())
		it := sv.MapRange()
		for it.Next() {
			k := reflect.New(dt.Key()).Elem()
			if err := store(k, it.Key().Interface(), depth+1); err != nil {
				return err
			}
			v := reflect.New(dt.Elem()).Elem()
			if err := store(v, it.Value().Interface(), depth+1); err != nil {
				return err
			}
			out.SetMapIndex(k, v)
		}
		dst.Set(out)
	case reflect.Struct:
		fields := structFields(dt)
		if sv.Kind() != reflect.Slice && sv.Kind() != reflect.Array || sv.Len() != len(fields) {
			return storeMismatch(src, dt)
		}
		for i, fi := range fields {
			if err := store(dst.Field(fi), sv.Index(i).Interface(), depth+1); err != nil {
				return fmt.Errorf("field %s: %w", dt.Field(fi).Name, err)
			}
		}
	default:
		return storeMismatch(src, dt)
	}
	return nil
}
