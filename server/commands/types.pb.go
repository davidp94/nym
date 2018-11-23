// Code generated by protoc-gen-go. DO NOT EDIT.
// source: server/commands/proto/types.proto

package commands

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	scheme "github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
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
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type StatusCode int32

const (
	StatusCode_OK                StatusCode = 0
	StatusCode_UNKNOWN           StatusCode = 1
	StatusCode_INVALID_COMMAND   StatusCode = 2
	StatusCode_INVALID_ARGUMENTS StatusCode = 3
	StatusCode_PROCESSING_ERROR  StatusCode = 4
	StatusCode_NOT_IMPLEMENTED   StatusCode = 5
	StatusCode_REQUEST_TIMEOUT   StatusCode = 6
	StatusCode_UNAVAILABLE       StatusCode = 7
)

var StatusCode_name = map[int32]string{
	0: "OK",
	1: "UNKNOWN",
	2: "INVALID_COMMAND",
	3: "INVALID_ARGUMENTS",
	4: "PROCESSING_ERROR",
	5: "NOT_IMPLEMENTED",
	6: "REQUEST_TIMEOUT",
	7: "UNAVAILABLE",
}

var StatusCode_value = map[string]int32{
	"OK":                0,
	"UNKNOWN":           1,
	"INVALID_COMMAND":   2,
	"INVALID_ARGUMENTS": 3,
	"PROCESSING_ERROR":  4,
	"NOT_IMPLEMENTED":   5,
	"REQUEST_TIMEOUT":   6,
	"UNAVAILABLE":       7,
}

func (x StatusCode) String() string {
	return proto.EnumName(StatusCode_name, int32(x))
}

func (StatusCode) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_ed9fc3098e7f53c0, []int{0}
}

type Status struct {
	Code                 int32    `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	Message              string   `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Status) Reset()         { *m = Status{} }
func (m *Status) String() string { return proto.CompactTextString(m) }
func (*Status) ProtoMessage()    {}
func (*Status) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed9fc3098e7f53c0, []int{0}
}

func (m *Status) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Status.Unmarshal(m, b)
}
func (m *Status) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Status.Marshal(b, m, deterministic)
}
func (m *Status) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Status.Merge(m, src)
}
func (m *Status) XXX_Size() int {
	return xxx_messageInfo_Status.Size(m)
}
func (m *Status) XXX_DiscardUnknown() {
	xxx_messageInfo_Status.DiscardUnknown(m)
}

var xxx_messageInfo_Status proto.InternalMessageInfo

func (m *Status) GetCode() int32 {
	if m != nil {
		return m.Code
	}
	return 0
}

func (m *Status) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

type SignRequest struct {
	PubM                 [][]byte `protobuf:"bytes,1,rep,name=pubM,proto3" json:"pubM,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRequest) Reset()         { *m = SignRequest{} }
func (m *SignRequest) String() string { return proto.CompactTextString(m) }
func (*SignRequest) ProtoMessage()    {}
func (*SignRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed9fc3098e7f53c0, []int{1}
}

func (m *SignRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRequest.Unmarshal(m, b)
}
func (m *SignRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRequest.Marshal(b, m, deterministic)
}
func (m *SignRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRequest.Merge(m, src)
}
func (m *SignRequest) XXX_Size() int {
	return xxx_messageInfo_SignRequest.Size(m)
}
func (m *SignRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SignRequest proto.InternalMessageInfo

func (m *SignRequest) GetPubM() [][]byte {
	if m != nil {
		return m.PubM
	}
	return nil
}

type SignResponse struct {
	Sig                  *scheme.ProtoSignature `protobuf:"bytes,1,opt,name=sig,proto3" json:"sig,omitempty"`
	Status               *Status                `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *SignResponse) Reset()         { *m = SignResponse{} }
func (m *SignResponse) String() string { return proto.CompactTextString(m) }
func (*SignResponse) ProtoMessage()    {}
func (*SignResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed9fc3098e7f53c0, []int{2}
}

func (m *SignResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignResponse.Unmarshal(m, b)
}
func (m *SignResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignResponse.Marshal(b, m, deterministic)
}
func (m *SignResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignResponse.Merge(m, src)
}
func (m *SignResponse) XXX_Size() int {
	return xxx_messageInfo_SignResponse.Size(m)
}
func (m *SignResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SignResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SignResponse proto.InternalMessageInfo

func (m *SignResponse) GetSig() *scheme.ProtoSignature {
	if m != nil {
		return m.Sig
	}
	return nil
}

func (m *SignResponse) GetStatus() *Status {
	if m != nil {
		return m.Status
	}
	return nil
}

type VerificationKeyRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VerificationKeyRequest) Reset()         { *m = VerificationKeyRequest{} }
func (m *VerificationKeyRequest) String() string { return proto.CompactTextString(m) }
func (*VerificationKeyRequest) ProtoMessage()    {}
func (*VerificationKeyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed9fc3098e7f53c0, []int{3}
}

func (m *VerificationKeyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerificationKeyRequest.Unmarshal(m, b)
}
func (m *VerificationKeyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerificationKeyRequest.Marshal(b, m, deterministic)
}
func (m *VerificationKeyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerificationKeyRequest.Merge(m, src)
}
func (m *VerificationKeyRequest) XXX_Size() int {
	return xxx_messageInfo_VerificationKeyRequest.Size(m)
}
func (m *VerificationKeyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VerificationKeyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VerificationKeyRequest proto.InternalMessageInfo

type VerificationKeyResponse struct {
	Vk                   *scheme.ProtoVerificationKey `protobuf:"bytes,1,opt,name=vk,proto3" json:"vk,omitempty"`
	Status               *Status                      `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *VerificationKeyResponse) Reset()         { *m = VerificationKeyResponse{} }
func (m *VerificationKeyResponse) String() string { return proto.CompactTextString(m) }
func (*VerificationKeyResponse) ProtoMessage()    {}
func (*VerificationKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed9fc3098e7f53c0, []int{4}
}

func (m *VerificationKeyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerificationKeyResponse.Unmarshal(m, b)
}
func (m *VerificationKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerificationKeyResponse.Marshal(b, m, deterministic)
}
func (m *VerificationKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerificationKeyResponse.Merge(m, src)
}
func (m *VerificationKeyResponse) XXX_Size() int {
	return xxx_messageInfo_VerificationKeyResponse.Size(m)
}
func (m *VerificationKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VerificationKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VerificationKeyResponse proto.InternalMessageInfo

func (m *VerificationKeyResponse) GetVk() *scheme.ProtoVerificationKey {
	if m != nil {
		return m.Vk
	}
	return nil
}

func (m *VerificationKeyResponse) GetStatus() *Status {
	if m != nil {
		return m.Status
	}
	return nil
}

type VerifyRequest struct {
	Sig                  *scheme.ProtoSignature `protobuf:"bytes,1,opt,name=sig,proto3" json:"sig,omitempty"`
	PubM                 [][]byte               `protobuf:"bytes,2,rep,name=pubM,proto3" json:"pubM,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *VerifyRequest) Reset()         { *m = VerifyRequest{} }
func (m *VerifyRequest) String() string { return proto.CompactTextString(m) }
func (*VerifyRequest) ProtoMessage()    {}
func (*VerifyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed9fc3098e7f53c0, []int{5}
}

func (m *VerifyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyRequest.Unmarshal(m, b)
}
func (m *VerifyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyRequest.Marshal(b, m, deterministic)
}
func (m *VerifyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyRequest.Merge(m, src)
}
func (m *VerifyRequest) XXX_Size() int {
	return xxx_messageInfo_VerifyRequest.Size(m)
}
func (m *VerifyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyRequest proto.InternalMessageInfo

func (m *VerifyRequest) GetSig() *scheme.ProtoSignature {
	if m != nil {
		return m.Sig
	}
	return nil
}

func (m *VerifyRequest) GetPubM() [][]byte {
	if m != nil {
		return m.PubM
	}
	return nil
}

type VerifyResponse struct {
	IsValid              bool     `protobuf:"varint,1,opt,name=isValid,proto3" json:"isValid,omitempty"`
	Status               *Status  `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VerifyResponse) Reset()         { *m = VerifyResponse{} }
func (m *VerifyResponse) String() string { return proto.CompactTextString(m) }
func (*VerifyResponse) ProtoMessage()    {}
func (*VerifyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ed9fc3098e7f53c0, []int{6}
}

func (m *VerifyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VerifyResponse.Unmarshal(m, b)
}
func (m *VerifyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VerifyResponse.Marshal(b, m, deterministic)
}
func (m *VerifyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyResponse.Merge(m, src)
}
func (m *VerifyResponse) XXX_Size() int {
	return xxx_messageInfo_VerifyResponse.Size(m)
}
func (m *VerifyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyResponse proto.InternalMessageInfo

func (m *VerifyResponse) GetIsValid() bool {
	if m != nil {
		return m.IsValid
	}
	return false
}

func (m *VerifyResponse) GetStatus() *Status {
	if m != nil {
		return m.Status
	}
	return nil
}

func init() {
	proto.RegisterEnum("commands.StatusCode", StatusCode_name, StatusCode_value)
	proto.RegisterType((*Status)(nil), "commands.Status")
	proto.RegisterType((*SignRequest)(nil), "commands.SignRequest")
	proto.RegisterType((*SignResponse)(nil), "commands.SignResponse")
	proto.RegisterType((*VerificationKeyRequest)(nil), "commands.VerificationKeyRequest")
	proto.RegisterType((*VerificationKeyResponse)(nil), "commands.VerificationKeyResponse")
	proto.RegisterType((*VerifyRequest)(nil), "commands.VerifyRequest")
	proto.RegisterType((*VerifyResponse)(nil), "commands.VerifyResponse")
}

func init() { proto.RegisterFile("server/commands/proto/types.proto", fileDescriptor_ed9fc3098e7f53c0) }

var fileDescriptor_ed9fc3098e7f53c0 = []byte{
	// 460 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x93, 0xdf, 0x6f, 0x93, 0x50,
	0x14, 0xc7, 0x85, 0x6e, 0x74, 0x1e, 0xa6, 0xbb, 0x5e, 0x7f, 0x8c, 0x98, 0x98, 0x74, 0xbc, 0x58,
	0x4d, 0x06, 0xc9, 0x4c, 0x7c, 0x67, 0x2d, 0x69, 0x48, 0xcb, 0xa5, 0x5e, 0xa0, 0x26, 0xbe, 0x34,
	0x94, 0x5e, 0x3b, 0x9c, 0xe5, 0x22, 0xf7, 0xd2, 0xa4, 0xfe, 0x31, 0xfe, 0xad, 0x06, 0x0a, 0x89,
	0x6e, 0x2f, 0xdb, 0xdb, 0xf9, 0xf1, 0x3d, 0x5f, 0x3e, 0xe7, 0x00, 0x70, 0x21, 0x58, 0xb9, 0x63,
	0xa5, 0x9d, 0xf2, 0xed, 0x36, 0xc9, 0xd7, 0xc2, 0x2e, 0x4a, 0x2e, 0xb9, 0x2d, 0xf7, 0x05, 0x13,
	0x56, 0x13, 0xe3, 0x93, 0xae, 0xf7, 0xf6, 0x7d, 0x5a, 0xee, 0x0b, 0xc9, 0xed, 0x94, 0xa7, 0x3c,
	0xaf, 0xa4, 0x2d, 0xd2, 0x1b, 0xb6, 0x65, 0xf7, 0x47, 0xcc, 0xcf, 0xa0, 0x85, 0x32, 0x91, 0x95,
	0xc0, 0x18, 0x8e, 0x52, 0xbe, 0x66, 0x86, 0x32, 0x50, 0x86, 0xc7, 0xb4, 0x89, 0xb1, 0x01, 0xfd,
	0x2d, 0x13, 0x22, 0xd9, 0x30, 0x43, 0x1d, 0x28, 0xc3, 0xa7, 0xb4, 0x4b, 0xcd, 0x0b, 0xd0, 0xc3,
	0x6c, 0x93, 0x53, 0xf6, 0xab, 0x62, 0x42, 0xd6, 0xc3, 0x45, 0xb5, 0xf2, 0x0d, 0x65, 0xd0, 0x1b,
	0x9e, 0xd2, 0x26, 0x36, 0x53, 0x38, 0x3d, 0x48, 0x44, 0xc1, 0x73, 0xc1, 0xf0, 0x07, 0xe8, 0x89,
	0x6c, 0xd3, 0xf8, 0xeb, 0x57, 0xe7, 0x56, 0x8b, 0x66, 0xcd, 0x6b, 0x8e, 0x5a, 0x98, 0xc8, 0xaa,
	0x64, 0xb4, 0xd6, 0xe0, 0x21, 0x68, 0xa2, 0xa1, 0x6a, 0x1e, 0xab, 0x5f, 0x21, 0xab, 0xdb, 0xcc,
	0x3a, 0xd0, 0xd2, 0xb6, 0x6f, 0x1a, 0xf0, 0x66, 0xc1, 0xca, 0xec, 0x7b, 0x96, 0x26, 0x32, 0xe3,
	0xf9, 0x94, 0xed, 0x5b, 0x24, 0xb3, 0x84, 0xf3, 0x7b, 0x9d, 0x96, 0xe4, 0x12, 0xd4, 0xdd, 0x6d,
	0x0b, 0xf2, 0xee, 0x7f, 0x90, 0xbb, 0x23, 0xea, 0xee, 0xf6, 0x11, 0x34, 0x04, 0x9e, 0x35, 0x06,
	0x1d, 0xc4, 0x63, 0x76, 0xee, 0x4e, 0xa8, 0xfe, 0x73, 0xc2, 0x08, 0x9e, 0x77, 0x7e, 0x2d, 0xba,
	0x01, 0xfd, 0x4c, 0x2c, 0x92, 0x9f, 0xd9, 0xba, 0x31, 0x3d, 0xa1, 0x5d, 0xfa, 0x70, 0xca, 0x8f,
	0x7f, 0x14, 0x80, 0x43, 0x69, 0x54, 0xbf, 0x64, 0x0d, 0xd4, 0x60, 0x8a, 0x9e, 0x60, 0x1d, 0xfa,
	0x31, 0x99, 0x92, 0xe0, 0x2b, 0x41, 0x0a, 0x7e, 0x09, 0x67, 0x1e, 0x59, 0x38, 0x33, 0x6f, 0xbc,
	0x1c, 0x05, 0xbe, 0xef, 0x90, 0x31, 0x52, 0xf1, 0x6b, 0x78, 0xd1, 0x15, 0x1d, 0x3a, 0x89, 0x7d,
	0x97, 0x44, 0x21, 0xea, 0xe1, 0x57, 0x80, 0xe6, 0x34, 0x18, 0xb9, 0x61, 0xe8, 0x91, 0xc9, 0xd2,
	0xa5, 0x34, 0xa0, 0xe8, 0xa8, 0x76, 0x20, 0x41, 0xb4, 0xf4, 0xfc, 0xf9, 0xcc, 0xad, 0x95, 0xee,
	0x18, 0x1d, 0xd7, 0x45, 0xea, 0x7e, 0x89, 0xdd, 0x30, 0x5a, 0x46, 0x9e, 0xef, 0x06, 0x71, 0x84,
	0x34, 0x7c, 0x06, 0x7a, 0x4c, 0x9c, 0x85, 0xe3, 0xcd, 0x9c, 0xeb, 0x99, 0x8b, 0xfa, 0xd7, 0xf6,
	0xb7, 0xcb, 0x4d, 0x26, 0x6f, 0xaa, 0x55, 0xbd, 0x82, 0xfd, 0x43, 0xc8, 0x2a, 0xfd, 0xbd, 0xcf,
	0xed, 0xd1, 0xe1, 0x7a, 0x13, 0x6e, 0xdf, 0xf9, 0x15, 0x56, 0x5a, 0xf3, 0x31, 0x7f, 0xfa, 0x1b,
	0x00, 0x00, 0xff, 0xff, 0x4d, 0x92, 0xde, 0x2e, 0x24, 0x03, 0x00, 0x00,
}
