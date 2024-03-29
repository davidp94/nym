// Code generated by protoc-gen-go. DO NOT EDIT.
// source: tendermint/nymabci/transaction/proto/types.proto

package transaction

import (
	scheme "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	_ "0xacab.org/jstuczyn/CoconutGo/crypto/elgamal"
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

type NewAccountRequest struct {
	// Public Key of the user used to derive account address and validate signature
	Address []byte `protobuf:"bytes,1,opt,name=Address,json=address,proto3" json:"Address,omitempty"`
	// represents some optional credential from an IP if required
	Credential []byte `protobuf:"bytes,2,opt,name=Credential,json=credential,proto3" json:"Credential,omitempty"`
	// Signature on request to confirm its validity + asserts knowledge of private key
	Sig                  []byte   `protobuf:"bytes,3,opt,name=Sig,json=sig,proto3" json:"Sig,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NewAccountRequest) Reset()         { *m = NewAccountRequest{} }
func (m *NewAccountRequest) String() string { return proto.CompactTextString(m) }
func (*NewAccountRequest) ProtoMessage()    {}
func (*NewAccountRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffb862c5130efc92, []int{0}
}

func (m *NewAccountRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NewAccountRequest.Unmarshal(m, b)
}
func (m *NewAccountRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NewAccountRequest.Marshal(b, m, deterministic)
}
func (m *NewAccountRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NewAccountRequest.Merge(m, src)
}
func (m *NewAccountRequest) XXX_Size() int {
	return xxx_messageInfo_NewAccountRequest.Size(m)
}
func (m *NewAccountRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_NewAccountRequest.DiscardUnknown(m)
}

var xxx_messageInfo_NewAccountRequest proto.InternalMessageInfo

func (m *NewAccountRequest) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *NewAccountRequest) GetCredential() []byte {
	if m != nil {
		return m.Credential
	}
	return nil
}

func (m *NewAccountRequest) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

// DEBUG
type AccountTransferRequest struct {
	// Used to validate signature + determine source address
	SourceAddress []byte `protobuf:"bytes,1,opt,name=SourceAddress,json=sourceAddress,proto3" json:"SourceAddress,omitempty"`
	// Used to determine target address
	TargetAddress []byte `protobuf:"bytes,2,opt,name=TargetAddress,json=targetAddress,proto3" json:"TargetAddress,omitempty"`
	// Amount to be transferred
	Amount uint64 `protobuf:"varint,3,opt,name=Amount,json=amount,proto3" json:"Amount,omitempty"`
	// While this function will only be available in debug and hence a nonce is really not needed,
	// I figured I should include it anyway as it's a good practice + will need to figure out a proper
	// nonce system anyway.
	Nonce []byte `protobuf:"bytes,4,opt,name=Nonce,json=nonce,proto3" json:"Nonce,omitempty"`
	// Signature on request to confirm its validitiy
	Sig                  []byte   `protobuf:"bytes,5,opt,name=Sig,json=sig,proto3" json:"Sig,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AccountTransferRequest) Reset()         { *m = AccountTransferRequest{} }
func (m *AccountTransferRequest) String() string { return proto.CompactTextString(m) }
func (*AccountTransferRequest) ProtoMessage()    {}
func (*AccountTransferRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffb862c5130efc92, []int{1}
}

func (m *AccountTransferRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AccountTransferRequest.Unmarshal(m, b)
}
func (m *AccountTransferRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AccountTransferRequest.Marshal(b, m, deterministic)
}
func (m *AccountTransferRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccountTransferRequest.Merge(m, src)
}
func (m *AccountTransferRequest) XXX_Size() int {
	return xxx_messageInfo_AccountTransferRequest.Size(m)
}
func (m *AccountTransferRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AccountTransferRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AccountTransferRequest proto.InternalMessageInfo

func (m *AccountTransferRequest) GetSourceAddress() []byte {
	if m != nil {
		return m.SourceAddress
	}
	return nil
}

func (m *AccountTransferRequest) GetTargetAddress() []byte {
	if m != nil {
		return m.TargetAddress
	}
	return nil
}

func (m *AccountTransferRequest) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *AccountTransferRequest) GetNonce() []byte {
	if m != nil {
		return m.Nonce
	}
	return nil
}

func (m *AccountTransferRequest) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

type TransferToPipeAccountNotification struct {
	// Used to identify the particular watcher and to verify signature
	WatcherPublicKey []byte `protobuf:"bytes,1,opt,name=WatcherPublicKey,json=watcherPublicKey,proto3" json:"WatcherPublicKey,omitempty"`
	// Ethereum address of the client
	ClientAddress []byte `protobuf:"bytes,2,opt,name=ClientAddress,json=clientAddress,proto3" json:"ClientAddress,omitempty"`
	// While right now it's completely unrequired as there is only a single pipe account, it might be useful
	// to have this information in the future if we decided to monitor multiple chains or have multiple pipe accounts
	// for example on epoch changes.
	PipeAccountAddress []byte `protobuf:"bytes,3,opt,name=PipeAccountAddress,json=pipeAccountAddress,proto3" json:"PipeAccountAddress,omitempty"`
	// Amount transferred by the client to the pipe account.
	Amount uint64 `protobuf:"varint,4,opt,name=Amount,json=amount,proto3" json:"Amount,omitempty"`
	// Hash of the transaction in which the transfer occured.
	// Used to distinguish from multiple transfers the client might have done.
	TxHash []byte `protobuf:"bytes,5,opt,name=TxHash,json=txHash,proto3" json:"TxHash,omitempty"`
	// Signature on the entire message done with the watcher's key.
	Sig                  []byte   `protobuf:"bytes,6,opt,name=Sig,json=sig,proto3" json:"Sig,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TransferToPipeAccountNotification) Reset()         { *m = TransferToPipeAccountNotification{} }
func (m *TransferToPipeAccountNotification) String() string { return proto.CompactTextString(m) }
func (*TransferToPipeAccountNotification) ProtoMessage()    {}
func (*TransferToPipeAccountNotification) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffb862c5130efc92, []int{2}
}

func (m *TransferToPipeAccountNotification) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TransferToPipeAccountNotification.Unmarshal(m, b)
}
func (m *TransferToPipeAccountNotification) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TransferToPipeAccountNotification.Marshal(b, m, deterministic)
}
func (m *TransferToPipeAccountNotification) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TransferToPipeAccountNotification.Merge(m, src)
}
func (m *TransferToPipeAccountNotification) XXX_Size() int {
	return xxx_messageInfo_TransferToPipeAccountNotification.Size(m)
}
func (m *TransferToPipeAccountNotification) XXX_DiscardUnknown() {
	xxx_messageInfo_TransferToPipeAccountNotification.DiscardUnknown(m)
}

var xxx_messageInfo_TransferToPipeAccountNotification proto.InternalMessageInfo

func (m *TransferToPipeAccountNotification) GetWatcherPublicKey() []byte {
	if m != nil {
		return m.WatcherPublicKey
	}
	return nil
}

func (m *TransferToPipeAccountNotification) GetClientAddress() []byte {
	if m != nil {
		return m.ClientAddress
	}
	return nil
}

func (m *TransferToPipeAccountNotification) GetPipeAccountAddress() []byte {
	if m != nil {
		return m.PipeAccountAddress
	}
	return nil
}

func (m *TransferToPipeAccountNotification) GetAmount() uint64 {
	if m != nil {
		return m.Amount
	}
	return 0
}

func (m *TransferToPipeAccountNotification) GetTxHash() []byte {
	if m != nil {
		return m.TxHash
	}
	return nil
}

func (m *TransferToPipeAccountNotification) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

type CredentialRequest struct {
	// Ethereum address of the client
	ClientAddress []byte `protobuf:"bytes,1,opt,name=ClientAddress,json=clientAddress,proto3" json:"ClientAddress,omitempty"`
	// While right now it's completely unrequired as there is only a single pipe account, it might be useful
	// to have this information in the future if we decided to monitor multiple chains or have multiple pipe accounts
	// for example on epoch changes.
	PipeAccountAddress []byte `protobuf:"bytes,2,opt,name=PipeAccountAddress,json=pipeAccountAddress,proto3" json:"PipeAccountAddress,omitempty"`
	// All the cryptographic materials required by issuers to perform a blind sign
	CryptoMaterials *scheme.ProtoBlindSignMaterials `protobuf:"bytes,3,opt,name=CryptoMaterials,json=cryptoMaterials,proto3" json:"CryptoMaterials,omitempty"`
	// Value of the credential. While it is included in a BIG form in CryptoMaterials, it's easier to operate on it
	// when it's an int. We can't send it as an uint64, as milagro requires a normal int argument to construct a BIG num.
	Value int64 `protobuf:"varint,4,opt,name=Value,json=value,proto3" json:"Value,omitempty"`
	// Required to prevent replay attacks.
	Nonce []byte `protobuf:"bytes,5,opt,name=Nonce,json=nonce,proto3" json:"Nonce,omitempty"`
	// Signature on entire request with client's ethereum key (so that client's address could be used to verify it)
	Sig                  []byte   `protobuf:"bytes,6,opt,name=Sig,json=sig,proto3" json:"Sig,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CredentialRequest) Reset()         { *m = CredentialRequest{} }
func (m *CredentialRequest) String() string { return proto.CompactTextString(m) }
func (*CredentialRequest) ProtoMessage()    {}
func (*CredentialRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ffb862c5130efc92, []int{3}
}

func (m *CredentialRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CredentialRequest.Unmarshal(m, b)
}
func (m *CredentialRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CredentialRequest.Marshal(b, m, deterministic)
}
func (m *CredentialRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CredentialRequest.Merge(m, src)
}
func (m *CredentialRequest) XXX_Size() int {
	return xxx_messageInfo_CredentialRequest.Size(m)
}
func (m *CredentialRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CredentialRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CredentialRequest proto.InternalMessageInfo

func (m *CredentialRequest) GetClientAddress() []byte {
	if m != nil {
		return m.ClientAddress
	}
	return nil
}

func (m *CredentialRequest) GetPipeAccountAddress() []byte {
	if m != nil {
		return m.PipeAccountAddress
	}
	return nil
}

func (m *CredentialRequest) GetCryptoMaterials() *scheme.ProtoBlindSignMaterials {
	if m != nil {
		return m.CryptoMaterials
	}
	return nil
}

func (m *CredentialRequest) GetValue() int64 {
	if m != nil {
		return m.Value
	}
	return 0
}

func (m *CredentialRequest) GetNonce() []byte {
	if m != nil {
		return m.Nonce
	}
	return nil
}

func (m *CredentialRequest) GetSig() []byte {
	if m != nil {
		return m.Sig
	}
	return nil
}

func init() {
	proto.RegisterType((*NewAccountRequest)(nil), "transaction.NewAccountRequest")
	proto.RegisterType((*AccountTransferRequest)(nil), "transaction.AccountTransferRequest")
	proto.RegisterType((*TransferToPipeAccountNotification)(nil), "transaction.TransferToPipeAccountNotification")
	proto.RegisterType((*CredentialRequest)(nil), "transaction.CredentialRequest")
}

func init() {
	proto.RegisterFile("tendermint/nymabci/transaction/proto/types.proto", fileDescriptor_ffb862c5130efc92)
}

var fileDescriptor_ffb862c5130efc92 = []byte{
	// 478 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x53, 0xd1, 0x6a, 0xd4, 0x40,
	0x14, 0x25, 0xdd, 0x26, 0x85, 0xa9, 0x4b, 0xb7, 0x83, 0x2c, 0xa1, 0x0f, 0xb2, 0x16, 0x41, 0xf1,
	0x21, 0x29, 0xfa, 0x2a, 0xc2, 0x76, 0x1f, 0x14, 0xc5, 0x65, 0xc9, 0x2e, 0x0a, 0xbe, 0xc8, 0x64,
	0x72, 0x9b, 0x1d, 0x49, 0x66, 0xe2, 0xcc, 0x8d, 0x6d, 0xfc, 0x1e, 0xff, 0xcd, 0x0f, 0xf0, 0x07,
	0x24, 0x93, 0xa4, 0xc9, 0x76, 0xb5, 0xf8, 0x96, 0x7b, 0xef, 0x99, 0x39, 0xe7, 0xe4, 0xdc, 0x21,
	0x17, 0x08, 0x32, 0x01, 0x9d, 0x0b, 0x89, 0xa1, 0xac, 0x72, 0x16, 0x73, 0x11, 0xa2, 0x66, 0xd2,
	0x30, 0x8e, 0x42, 0xc9, 0xb0, 0xd0, 0x0a, 0x55, 0x88, 0x55, 0x01, 0x26, 0xb0, 0xdf, 0xf4, 0x78,
	0x30, 0x3e, 0x7b, 0xca, 0x75, 0x55, 0xa0, 0x0a, 0xb9, 0xe2, 0x4a, 0x96, 0x18, 0x1a, 0xbe, 0x85,
	0x1c, 0xf6, 0x4f, 0x9d, 0x05, 0xf7, 0x02, 0xcb, 0x3c, 0xce, 0x40, 0x0f, 0xf1, 0xb3, 0x16, 0x0f,
	0x59, 0xca, 0x72, 0x96, 0xed, 0xdf, 0x78, 0xfe, 0x85, 0x9c, 0x2e, 0xe1, 0x7a, 0xce, 0xb9, 0x2a,
	0x25, 0x46, 0xf0, 0xad, 0x04, 0x83, 0xd4, 0x27, 0x47, 0xf3, 0x24, 0xd1, 0x60, 0x8c, 0xef, 0xcc,
	0x9c, 0x67, 0x0f, 0xa2, 0x23, 0xd6, 0x94, 0xf4, 0x11, 0x21, 0x0b, 0x0d, 0x09, 0x48, 0x14, 0x2c,
	0xf3, 0x0f, 0xec, 0x90, 0xf0, 0xdb, 0x0e, 0x9d, 0x90, 0xd1, 0x5a, 0xa4, 0xfe, 0xc8, 0x0e, 0x46,
	0x46, 0xa4, 0xe7, 0x3f, 0x1d, 0x32, 0x6d, 0xaf, 0xdf, 0xd4, 0x96, 0xaf, 0x40, 0x77, 0x34, 0x4f,
	0xc8, 0x78, 0xad, 0x4a, 0xcd, 0x61, 0x97, 0x6c, 0x6c, 0x86, 0xcd, 0x1a, 0xb5, 0x61, 0x3a, 0x05,
	0xec, 0x50, 0x0d, 0xeb, 0x18, 0x87, 0x4d, 0x3a, 0x25, 0xde, 0x3c, 0xaf, 0x49, 0x2c, 0xf7, 0x61,
	0xe4, 0x31, 0x5b, 0xd1, 0x87, 0xc4, 0x5d, 0x2a, 0xc9, 0xc1, 0x3f, 0xb4, 0xa7, 0x5c, 0x59, 0x17,
	0x9d, 0x4c, 0xb7, 0x97, 0xf9, 0xcb, 0x21, 0x8f, 0x3b, 0x7d, 0x1b, 0xb5, 0x12, 0x05, 0xb4, 0xa2,
	0x97, 0x0a, 0xc5, 0x95, 0xe0, 0xac, 0x0e, 0x8a, 0x3e, 0x27, 0x93, 0x4f, 0x0c, 0xf9, 0x16, 0xf4,
	0xaa, 0x8c, 0x33, 0xc1, 0xdf, 0x43, 0xd5, 0x8a, 0x9e, 0x5c, 0xdf, 0xe9, 0xd7, 0xba, 0x17, 0x99,
	0x00, 0x79, 0x57, 0x37, 0x1f, 0x36, 0x69, 0x40, 0xe8, 0x80, 0xac, 0x83, 0x36, 0xff, 0x8f, 0x16,
	0x7b, 0x93, 0x81, 0xcf, 0xc3, 0x1d, 0x9f, 0x53, 0xe2, 0x6d, 0x6e, 0xde, 0x32, 0xb3, 0x6d, 0x4d,
	0x79, 0x68, 0xab, 0xce, 0xa9, 0xd7, 0x3b, 0xfd, 0xed, 0x90, 0xd3, 0x3e, 0xc3, 0x41, 0x16, 0xbb,
	0x6a, 0x9d, 0xff, 0x57, 0x7b, 0xf0, 0x4f, 0xb5, 0xef, 0xc8, 0xc9, 0xc2, 0x6e, 0xe0, 0x07, 0x86,
	0xa0, 0x05, 0xcb, 0x1a, 0x6b, 0xc7, 0x2f, 0x66, 0x41, 0xbb, 0xc2, 0xc1, 0xaa, 0x5e, 0xc3, 0xcb,
	0x4c, 0xc8, 0x64, 0x2d, 0x52, 0x79, 0x8b, 0x8b, 0x4e, 0xf8, 0xee, 0xc1, 0x3a, 0xc9, 0x8f, 0x2c,
	0x2b, 0x9b, 0x24, 0x47, 0x91, 0xfb, 0xbd, 0x2e, 0xfa, 0x7c, 0xdd, 0xbf, 0xe4, 0xdb, 0xbb, 0xbe,
	0x7c, 0xfd, 0xf9, 0xd5, 0xc5, 0x0d, 0xe3, 0x2c, 0x0e, 0x94, 0x4e, 0xc3, 0xaf, 0x06, 0x4b, 0xfe,
	0xa3, 0x92, 0xe1, 0xa2, 0x51, 0xf1, 0x46, 0x85, 0xf7, 0xbf, 0xe0, 0xd8, 0xb3, 0xcf, 0xe5, 0xe5,
	0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xf8, 0x42, 0xe8, 0x55, 0xea, 0x03, 0x00, 0x00,
}
