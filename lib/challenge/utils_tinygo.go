//go:build tinygo

package challenge

// #include <stdlib.h>
import "C"
import (
	"unsafe"
)

// PtrToBytes returns a byte slice from WebAssembly compatible numeric types
// representing its pointer and length.
func PtrToBytes(ptr uint32, size uint32) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

// BytesToPtr returns a pointer and size pair for the given byte slice in a way
// compatible with WebAssembly numeric types.
// The returned pointer aliases the slice hence the slice must be kept alive
// until ptr is no longer needed.
func BytesToPtr(s []byte) (uint32, uint32) {
	ptr := unsafe.Pointer(unsafe.SliceData(s))
	return uint32(uintptr(ptr)), uint32(len(s))
}

// BytesToLeakedPtr returns a pointer and size pair for the given byte slice in a way
// compatible with WebAssembly numeric types.
// The pointer is not automatically managed by TinyGo hence it must be freed by the host.
func BytesToLeakedPtr(s []byte) (uint32, uint32) {
	size := C.ulong(len(s))
	ptr := unsafe.Pointer(C.malloc(size))
	copy(unsafe.Slice((*byte)(ptr), size), s)
	return uint32(uintptr(ptr)), uint32(size)
}

// PtrToString returns a string from WebAssembly compatible numeric types
// representing its pointer and length.
func PtrToString(ptr uint32, size uint32) string {
	return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

// StringToPtr returns a pointer and size pair for the given string in a way
// compatible with WebAssembly numeric types.
// The returned pointer aliases the string hence the string must be kept alive
// until ptr is no longer needed.
func StringToPtr(s string) (uint32, uint32) {
	ptr := unsafe.Pointer(unsafe.StringData(s))
	return uint32(uintptr(ptr)), uint32(len(s))
}

// StringToLeakedPtr returns a pointer and size pair for the given string in a way
// compatible with WebAssembly numeric types.
// The pointer is not automatically managed by TinyGo hence it must be freed by the host.
func StringToLeakedPtr(s string) (uint32, uint32) {
	size := C.ulong(len(s))
	ptr := unsafe.Pointer(C.malloc(size))
	copy(unsafe.Slice((*byte)(ptr), size), s)
	return uint32(uintptr(ptr)), uint32(size)
}
