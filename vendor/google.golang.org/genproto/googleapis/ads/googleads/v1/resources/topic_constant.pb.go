// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/resources/topic_constant.proto

package resources

import (
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

// Use topics to target or exclude placements in the Google Display Network
// based on the category into which the placement falls (for example,
// "Pets & Animals/Pets/Dogs").
type TopicConstant struct {
	// The resource name of the topic constant.
	// topic constant resource names have the form:
	//
	// `topicConstants/{topic_id}`
	ResourceName string `protobuf:"bytes,1,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	// The ID of the topic.
	Id *wrappers.Int64Value `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	// Resource name of parent of the topic constant.
	TopicConstantParent *wrappers.StringValue `protobuf:"bytes,3,opt,name=topic_constant_parent,json=topicConstantParent,proto3" json:"topic_constant_parent,omitempty"`
	// The category to target or exclude. Each subsequent element in the array
	// describes a more specific sub-category. For example,
	// {"Pets & Animals", "Pets", "Dogs"} represents the
	// "Pets & Animals/Pets/Dogs" category. A complete list of available topic
	// categories is available
	// <a
	// href="https://developers.google.com/adwords/api/docs/appendix/verticals">
	// here</a>
	Path                 []*wrappers.StringValue `protobuf:"bytes,4,rep,name=path,proto3" json:"path,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                `json:"-"`
	XXX_unrecognized     []byte                  `json:"-"`
	XXX_sizecache        int32                   `json:"-"`
}

func (m *TopicConstant) Reset()         { *m = TopicConstant{} }
func (m *TopicConstant) String() string { return proto.CompactTextString(m) }
func (*TopicConstant) ProtoMessage()    {}
func (*TopicConstant) Descriptor() ([]byte, []int) {
	return fileDescriptor_7e0961a18b03751e, []int{0}
}

func (m *TopicConstant) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TopicConstant.Unmarshal(m, b)
}
func (m *TopicConstant) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TopicConstant.Marshal(b, m, deterministic)
}
func (m *TopicConstant) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TopicConstant.Merge(m, src)
}
func (m *TopicConstant) XXX_Size() int {
	return xxx_messageInfo_TopicConstant.Size(m)
}
func (m *TopicConstant) XXX_DiscardUnknown() {
	xxx_messageInfo_TopicConstant.DiscardUnknown(m)
}

var xxx_messageInfo_TopicConstant proto.InternalMessageInfo

func (m *TopicConstant) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *TopicConstant) GetId() *wrappers.Int64Value {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *TopicConstant) GetTopicConstantParent() *wrappers.StringValue {
	if m != nil {
		return m.TopicConstantParent
	}
	return nil
}

func (m *TopicConstant) GetPath() []*wrappers.StringValue {
	if m != nil {
		return m.Path
	}
	return nil
}

func init() {
	proto.RegisterType((*TopicConstant)(nil), "google.ads.googleads.v1.resources.TopicConstant")
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/resources/topic_constant.proto", fileDescriptor_7e0961a18b03751e)
}

var fileDescriptor_7e0961a18b03751e = []byte{
	// 360 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x91, 0x4f, 0x4b, 0xf3, 0x30,
	0x00, 0xc6, 0x69, 0x37, 0x5e, 0x78, 0xfb, 0xbe, 0xbb, 0x54, 0x84, 0x32, 0x87, 0x6c, 0xca, 0x60,
	0x20, 0xa4, 0x56, 0x65, 0x87, 0x78, 0xea, 0x3c, 0x0c, 0x3d, 0x48, 0x99, 0xd2, 0x83, 0x14, 0x46,
	0xd6, 0xc6, 0x1a, 0xd8, 0x92, 0x90, 0x64, 0xf3, 0xfb, 0x78, 0xf4, 0xa3, 0xf8, 0x3d, 0xbc, 0xf8,
	0x25, 0x94, 0x36, 0x4d, 0x70, 0x08, 0xee, 0xf6, 0xd0, 0xfc, 0x9e, 0x3f, 0x4d, 0xbc, 0x71, 0xc9,
	0x58, 0xb9, 0xc4, 0x21, 0x2a, 0x64, 0xa8, 0x65, 0xa5, 0x36, 0x51, 0x28, 0xb0, 0x64, 0x6b, 0x91,
	0x63, 0x19, 0x2a, 0xc6, 0x49, 0x3e, 0xcf, 0x19, 0x95, 0x0a, 0x51, 0x05, 0xb8, 0x60, 0x8a, 0xf9,
	0x03, 0x0d, 0x03, 0x54, 0x48, 0x60, 0x7d, 0x60, 0x13, 0x01, 0xeb, 0xeb, 0x1e, 0x36, 0xd1, 0xb5,
	0x61, 0xb1, 0x7e, 0x0c, 0x9f, 0x05, 0xe2, 0x1c, 0x0b, 0xa9, 0x23, 0xba, 0x3d, 0x53, 0xcd, 0x49,
	0x88, 0x28, 0x65, 0x0a, 0x29, 0xc2, 0x68, 0x73, 0x7a, 0xf4, 0xee, 0x78, 0x9d, 0xfb, 0xaa, 0xf9,
	0xaa, 0x29, 0xf6, 0x8f, 0xbd, 0x8e, 0x09, 0x9f, 0x53, 0xb4, 0xc2, 0x81, 0xd3, 0x77, 0x46, 0x7f,
	0x67, 0xff, 0xcd, 0xc7, 0x5b, 0xb4, 0xc2, 0xfe, 0x89, 0xe7, 0x92, 0x22, 0x70, 0xfb, 0xce, 0xe8,
	0xdf, 0xd9, 0x41, 0xb3, 0x0c, 0x98, 0x05, 0xe0, 0x9a, 0xaa, 0xf1, 0x45, 0x8a, 0x96, 0x6b, 0x3c,
	0x73, 0x49, 0xe1, 0x27, 0xde, 0xfe, 0xf6, 0xcf, 0xcd, 0x39, 0x12, 0x98, 0xaa, 0xa0, 0x55, 0xfb,
	0x7b, 0x3f, 0xfc, 0x77, 0x4a, 0x10, 0x5a, 0xea, 0x80, 0x3d, 0xf5, 0x7d, 0x5d, 0x52, 0x1b, 0xfd,
	0x53, 0xaf, 0xcd, 0x91, 0x7a, 0x0a, 0xda, 0xfd, 0xd6, 0xce, 0x80, 0x9a, 0x9c, 0x7c, 0x3a, 0xde,
	0x30, 0x67, 0x2b, 0xb0, 0xf3, 0x3e, 0x27, 0xfe, 0xd6, 0x75, 0x24, 0x55, 0x64, 0xe2, 0x3c, 0xdc,
	0x34, 0xc6, 0x92, 0x2d, 0x11, 0x2d, 0x01, 0x13, 0x65, 0x58, 0x62, 0x5a, 0x17, 0x9a, 0x07, 0xe5,
	0x44, 0xfe, 0xf2, 0xbe, 0x97, 0x56, 0xbd, 0xb8, 0xad, 0x69, 0x1c, 0xbf, 0xba, 0x83, 0xa9, 0x8e,
	0x8c, 0x0b, 0x09, 0xb4, 0xac, 0x54, 0x1a, 0x81, 0x99, 0x21, 0xdf, 0x0c, 0x93, 0xc5, 0x85, 0xcc,
	0x2c, 0x93, 0xa5, 0x51, 0x66, 0x99, 0x0f, 0x77, 0xa8, 0x0f, 0x20, 0x8c, 0x0b, 0x09, 0xa1, 0xa5,
	0x20, 0x4c, 0x23, 0x08, 0x2d, 0xb7, 0xf8, 0x53, 0x8f, 0x3d, 0xff, 0x0a, 0x00, 0x00, 0xff, 0xff,
	0xc1, 0x88, 0x02, 0x04, 0x8b, 0x02, 0x00, 0x00,
}
