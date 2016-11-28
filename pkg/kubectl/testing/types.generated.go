/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// ************************************************************
// DO NOT EDIT.
// THIS FILE IS AUTO-GENERATED BY codecgen.
// ************************************************************

package testing

import (
	"errors"
	"fmt"
	codec1978 "github.com/ugorji/go/codec"
	pkg2_api "k8s.io/kubernetes/pkg/api"
	pkg1_v1 "k8s.io/kubernetes/pkg/apis/meta/v1"
	pkg3_types "k8s.io/kubernetes/pkg/types"
	"reflect"
	"runtime"
	time "time"
)

const (
	// ----- content types ----
	codecSelferC_UTF81234 = 1
	codecSelferC_RAW1234  = 0
	// ----- value types used ----
	codecSelferValueTypeArray1234 = 10
	codecSelferValueTypeMap1234   = 9
	// ----- containerStateValues ----
	codecSelfer_containerMapKey1234    = 2
	codecSelfer_containerMapValue1234  = 3
	codecSelfer_containerMapEnd1234    = 4
	codecSelfer_containerArrayElem1234 = 6
	codecSelfer_containerArrayEnd1234  = 7
)

var (
	codecSelferBitsize1234                         = uint8(reflect.TypeOf(uint(0)).Bits())
	codecSelferOnlyMapOrArrayEncodeToStructErr1234 = errors.New(`only encoded map or array can be decoded into a struct`)
)

type codecSelfer1234 struct{}

func init() {
	if codec1978.GenVersion != 5 {
		_, file, _, _ := runtime.Caller(0)
		err := fmt.Errorf("codecgen version mismatch: current: %v, need %v. Re-generate file: %v",
			5, codec1978.GenVersion, file)
		panic(err)
	}
	if false { // reference the types, but skip this branch at build/run time
		var v0 pkg2_api.ObjectMeta
		var v1 pkg1_v1.TypeMeta
		var v2 pkg3_types.UID
		var v3 time.Time
		_, _, _, _ = v0, v1, v2, v3
	}
}

func (x *TestStruct) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym1 := z.EncBinary()
		_ = yym1
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep2 := !z.EncBinary()
			yy2arr2 := z.EncBasicHandle().StructToArray
			var yyq2 [7]bool
			_, _, _ = yysep2, yyq2, yy2arr2
			const yyr2 bool = false
			yyq2[0] = x.Kind != ""
			yyq2[1] = x.APIVersion != ""
			yyq2[2] = true
			var yynn2 int
			if yyr2 || yy2arr2 {
				r.EncodeArrayStart(7)
			} else {
				yynn2 = 4
				for _, b := range yyq2 {
					if b {
						yynn2++
					}
				}
				r.EncodeMapStart(yynn2)
				yynn2 = 0
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[0] {
					yym4 := z.EncBinary()
					_ = yym4
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq2[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("kind"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym5 := z.EncBinary()
					_ = yym5
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[1] {
					yym7 := z.EncBinary()
					_ = yym7
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq2[1] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("apiVersion"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym8 := z.EncBinary()
					_ = yym8
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[2] {
					yy10 := &x.ObjectMeta
					yy10.CodecEncodeSelf(e)
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq2[2] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("metadata"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yy11 := &x.ObjectMeta
					yy11.CodecEncodeSelf(e)
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yym13 := z.EncBinary()
				_ = yym13
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.Key))
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("Key"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yym14 := z.EncBinary()
				_ = yym14
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.Key))
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if x.Map == nil {
					r.EncodeNil()
				} else {
					yym16 := z.EncBinary()
					_ = yym16
					if false {
					} else {
						z.F.EncMapStringIntV(x.Map, false, e)
					}
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("Map"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				if x.Map == nil {
					r.EncodeNil()
				} else {
					yym17 := z.EncBinary()
					_ = yym17
					if false {
					} else {
						z.F.EncMapStringIntV(x.Map, false, e)
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if x.StringList == nil {
					r.EncodeNil()
				} else {
					yym19 := z.EncBinary()
					_ = yym19
					if false {
					} else {
						z.F.EncSliceStringV(x.StringList, false, e)
					}
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("StringList"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				if x.StringList == nil {
					r.EncodeNil()
				} else {
					yym20 := z.EncBinary()
					_ = yym20
					if false {
					} else {
						z.F.EncSliceStringV(x.StringList, false, e)
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if x.IntList == nil {
					r.EncodeNil()
				} else {
					yym22 := z.EncBinary()
					_ = yym22
					if false {
					} else {
						z.F.EncSliceIntV(x.IntList, false, e)
					}
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("IntList"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				if x.IntList == nil {
					r.EncodeNil()
				} else {
					yym23 := z.EncBinary()
					_ = yym23
					if false {
					} else {
						z.F.EncSliceIntV(x.IntList, false, e)
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *TestStruct) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym24 := z.DecBinary()
	_ = yym24
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct25 := r.ContainerType()
		if yyct25 == codecSelferValueTypeMap1234 {
			yyl25 := r.ReadMapStart()
			if yyl25 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl25, d)
			}
		} else if yyct25 == codecSelferValueTypeArray1234 {
			yyl25 := r.ReadArrayStart()
			if yyl25 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl25, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *TestStruct) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys26Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys26Slc
	var yyhl26 bool = l >= 0
	for yyj26 := 0; ; yyj26++ {
		if yyhl26 {
			if yyj26 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys26Slc = r.DecodeBytes(yys26Slc, true, true)
		yys26 := string(yys26Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys26 {
		case "kind":
			if r.TryDecodeAsNil() {
				x.Kind = ""
			} else {
				x.Kind = string(r.DecodeString())
			}
		case "apiVersion":
			if r.TryDecodeAsNil() {
				x.APIVersion = ""
			} else {
				x.APIVersion = string(r.DecodeString())
			}
		case "metadata":
			if r.TryDecodeAsNil() {
				x.ObjectMeta = pkg2_api.ObjectMeta{}
			} else {
				yyv29 := &x.ObjectMeta
				yyv29.CodecDecodeSelf(d)
			}
		case "Key":
			if r.TryDecodeAsNil() {
				x.Key = ""
			} else {
				x.Key = string(r.DecodeString())
			}
		case "Map":
			if r.TryDecodeAsNil() {
				x.Map = nil
			} else {
				yyv31 := &x.Map
				yym32 := z.DecBinary()
				_ = yym32
				if false {
				} else {
					z.F.DecMapStringIntX(yyv31, false, d)
				}
			}
		case "StringList":
			if r.TryDecodeAsNil() {
				x.StringList = nil
			} else {
				yyv33 := &x.StringList
				yym34 := z.DecBinary()
				_ = yym34
				if false {
				} else {
					z.F.DecSliceStringX(yyv33, false, d)
				}
			}
		case "IntList":
			if r.TryDecodeAsNil() {
				x.IntList = nil
			} else {
				yyv35 := &x.IntList
				yym36 := z.DecBinary()
				_ = yym36
				if false {
				} else {
					z.F.DecSliceIntX(yyv35, false, d)
				}
			}
		default:
			z.DecStructFieldNotFound(-1, yys26)
		} // end switch yys26
	} // end for yyj26
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *TestStruct) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj37 int
	var yyb37 bool
	var yyhl37 bool = l >= 0
	yyj37++
	if yyhl37 {
		yyb37 = yyj37 > l
	} else {
		yyb37 = r.CheckBreak()
	}
	if yyb37 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Kind = ""
	} else {
		x.Kind = string(r.DecodeString())
	}
	yyj37++
	if yyhl37 {
		yyb37 = yyj37 > l
	} else {
		yyb37 = r.CheckBreak()
	}
	if yyb37 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.APIVersion = ""
	} else {
		x.APIVersion = string(r.DecodeString())
	}
	yyj37++
	if yyhl37 {
		yyb37 = yyj37 > l
	} else {
		yyb37 = r.CheckBreak()
	}
	if yyb37 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.ObjectMeta = pkg2_api.ObjectMeta{}
	} else {
		yyv40 := &x.ObjectMeta
		yyv40.CodecDecodeSelf(d)
	}
	yyj37++
	if yyhl37 {
		yyb37 = yyj37 > l
	} else {
		yyb37 = r.CheckBreak()
	}
	if yyb37 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Key = ""
	} else {
		x.Key = string(r.DecodeString())
	}
	yyj37++
	if yyhl37 {
		yyb37 = yyj37 > l
	} else {
		yyb37 = r.CheckBreak()
	}
	if yyb37 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Map = nil
	} else {
		yyv42 := &x.Map
		yym43 := z.DecBinary()
		_ = yym43
		if false {
		} else {
			z.F.DecMapStringIntX(yyv42, false, d)
		}
	}
	yyj37++
	if yyhl37 {
		yyb37 = yyj37 > l
	} else {
		yyb37 = r.CheckBreak()
	}
	if yyb37 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.StringList = nil
	} else {
		yyv44 := &x.StringList
		yym45 := z.DecBinary()
		_ = yym45
		if false {
		} else {
			z.F.DecSliceStringX(yyv44, false, d)
		}
	}
	yyj37++
	if yyhl37 {
		yyb37 = yyj37 > l
	} else {
		yyb37 = r.CheckBreak()
	}
	if yyb37 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.IntList = nil
	} else {
		yyv46 := &x.IntList
		yym47 := z.DecBinary()
		_ = yym47
		if false {
		} else {
			z.F.DecSliceIntX(yyv46, false, d)
		}
	}
	for {
		yyj37++
		if yyhl37 {
			yyb37 = yyj37 > l
		} else {
			yyb37 = r.CheckBreak()
		}
		if yyb37 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj37-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}
