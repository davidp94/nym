// Code generated by protoc-gen-go. DO NOT EDIT.
// source: crypto/coconut/scheme/proto/tumblertypes.proto

package coconut

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type ProtoThetaTumbler struct {
	Theta                *ProtoTheta `protobuf:"bytes,1,opt,name=theta,proto3" json:"theta,omitempty"`
	Zeta                 []byte      `protobuf:"bytes,2,opt,name=zeta,proto3" json:"zeta,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *ProtoThetaTumbler) Reset()         { *m = ProtoThetaTumbler{} }
func (m *ProtoThetaTumbler) String() string { return proto.CompactTextString(m) }
func (*ProtoThetaTumbler) ProtoMessage()    {}
func (*ProtoThetaTumbler) Descriptor() ([]byte, []int) {
	return fileDescriptor_d8ab20651969e128, []int{0}
}

func (m *ProtoThetaTumbler) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProtoThetaTumbler.Unmarshal(m, b)
}
func (m *ProtoThetaTumbler) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProtoThetaTumbler.Marshal(b, m, deterministic)
}
func (m *ProtoThetaTumbler) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProtoThetaTumbler.Merge(m, src)
}
func (m *ProtoThetaTumbler) XXX_Size() int {
	return xxx_messageInfo_ProtoThetaTumbler.Size(m)
}
func (m *ProtoThetaTumbler) XXX_DiscardUnknown() {
	xxx_messageInfo_ProtoThetaTumbler.DiscardUnknown(m)
}

var xxx_messageInfo_ProtoThetaTumbler proto.InternalMessageInfo

func (m *ProtoThetaTumbler) GetTheta() *ProtoTheta {
	if m != nil {
		return m.Theta
	}
	return nil
}

func (m *ProtoThetaTumbler) GetZeta() []byte {
	if m != nil {
		return m.Zeta
	}
	return nil
}

func init() {
	proto.RegisterType((*ProtoThetaTumbler)(nil), "coconut.ProtoThetaTumbler")
}

func init() {
	proto.RegisterFile("crypto/coconut/scheme/proto/tumblertypes.proto", fileDescriptor_d8ab20651969e128)
}

var fileDescriptor_d8ab20651969e128 = []byte{
	// 171 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x4b, 0x2e, 0xaa, 0x2c,
	0x28, 0xc9, 0xd7, 0x4f, 0xce, 0x4f, 0xce, 0xcf, 0x2b, 0x2d, 0xd1, 0x2f, 0x4e, 0xce, 0x48, 0xcd,
	0x4d, 0xd5, 0x2f, 0x28, 0xca, 0x2f, 0xc9, 0xd7, 0x2f, 0x29, 0xcd, 0x4d, 0xca, 0x49, 0x2d, 0x2a,
	0xa9, 0x2c, 0x48, 0x2d, 0xd6, 0x03, 0x0b, 0x09, 0xb1, 0x43, 0x15, 0x4a, 0xa9, 0xe3, 0xd5, 0x88,
	0xd0, 0xa1, 0x14, 0xc4, 0x25, 0x18, 0x00, 0x62, 0x84, 0x64, 0xa4, 0x96, 0x24, 0x86, 0x40, 0x4c,
	0x14, 0xd2, 0xe4, 0x62, 0x2d, 0x01, 0xf1, 0x25, 0x18, 0x15, 0x18, 0x35, 0xb8, 0x8d, 0x84, 0xf5,
	0xa0, 0xc6, 0xe8, 0x21, 0x94, 0x06, 0x41, 0x54, 0x08, 0x09, 0x71, 0xb1, 0x54, 0x81, 0x54, 0x32,
	0x29, 0x30, 0x6a, 0xf0, 0x04, 0x81, 0xd9, 0x4e, 0xa6, 0x51, 0xc6, 0x06, 0x15, 0x89, 0xc9, 0x89,
	0x49, 0x7a, 0xf9, 0x45, 0xe9, 0xfa, 0x59, 0xc5, 0x25, 0xa5, 0xc9, 0x55, 0x95, 0x79, 0xfa, 0xce,
	0x10, 0x43, 0xdc, 0xf3, 0xf5, 0xb1, 0x3a, 0x2e, 0x89, 0x0d, 0xec, 0x22, 0x63, 0x40, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x72, 0x15, 0xd8, 0x6f, 0xf5, 0x00, 0x00, 0x00,
}