//go:build !tinygo || !wasip1

package _interface

func PtrToBytes(ptr uint32, size uint32) []byte   { panic("not implemented") }
func BytesToPtr(s []byte) (uint32, uint32)        { panic("not implemented") }
func BytesToLeakedPtr(s []byte) (uint32, uint32)  { panic("not implemented") }
func PtrToString(ptr uint32, size uint32) string  { panic("not implemented") }
func StringToPtr(s string) (uint32, uint32)       { panic("not implemented") }
func StringToLeakedPtr(s string) (uint32, uint32) { panic("not implemented") }
