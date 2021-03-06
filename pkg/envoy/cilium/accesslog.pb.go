// Code generated by protoc-gen-go. DO NOT EDIT.
// source: cilium/accesslog.proto

/*
Package cilium is a generated protocol buffer package.

It is generated from these files:
	cilium/accesslog.proto
	cilium/cilium_bpf_metadata.proto
	cilium/cilium_l7policy.proto
	cilium/npds.proto
	cilium/nphds.proto

It has these top-level messages:
	KeyValue
	HttpLogEntry
	BpfMetadata
	L7Policy
	NetworkPolicy
	DirectionNetworkPolicy
	PortNetworkPolicy
	PortNetworkPolicyRule
	HttpNetworkPolicyRules
	HttpNetworkPolicyRule
	NetworkPolicyHosts
*/
package cilium

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Protocol int32

const (
	Protocol_HTTP10 Protocol = 0
	Protocol_HTTP11 Protocol = 1
	Protocol_HTTP2  Protocol = 2
)

var Protocol_name = map[int32]string{
	0: "HTTP10",
	1: "HTTP11",
	2: "HTTP2",
}
var Protocol_value = map[string]int32{
	"HTTP10": 0,
	"HTTP11": 1,
	"HTTP2":  2,
}

func (x Protocol) String() string {
	return proto.EnumName(Protocol_name, int32(x))
}
func (Protocol) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type EntryType int32

const (
	EntryType_Request  EntryType = 0
	EntryType_Response EntryType = 1
	EntryType_Denied   EntryType = 2
)

var EntryType_name = map[int32]string{
	0: "Request",
	1: "Response",
	2: "Denied",
}
var EntryType_value = map[string]int32{
	"Request":  0,
	"Response": 1,
	"Denied":   2,
}

func (x EntryType) String() string {
	return proto.EnumName(EntryType_name, int32(x))
}
func (EntryType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type KeyValue struct {
	Key   string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
}

func (m *KeyValue) Reset()                    { *m = KeyValue{} }
func (m *KeyValue) String() string            { return proto.CompactTextString(m) }
func (*KeyValue) ProtoMessage()               {}
func (*KeyValue) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *KeyValue) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *KeyValue) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type HttpLogEntry struct {
	// The time that Cilium filter captured this log entry,
	// in, nanoseconds since 1/1/1970.
	Timestamp    uint64    `protobuf:"varint,1,opt,name=timestamp" json:"timestamp,omitempty"`
	HttpProtocol Protocol  `protobuf:"varint,2,opt,name=http_protocol,json=httpProtocol,enum=cilium.Protocol" json:"http_protocol,omitempty"`
	EntryType    EntryType `protobuf:"varint,3,opt,name=entry_type,json=entryType,enum=cilium.EntryType" json:"entry_type,omitempty"`
	// Cilium Redirect resource name
	CiliumResourceName string `protobuf:"bytes,4,opt,name=cilium_resource_name,json=ciliumResourceName" json:"cilium_resource_name,omitempty"`
	// Cilium rule reference
	CiliumRuleRef string `protobuf:"bytes,5,opt,name=cilium_rule_ref,json=ciliumRuleRef" json:"cilium_rule_ref,omitempty"`
	// Cilium security ID of the source
	SourceSecurityId uint32 `protobuf:"varint,6,opt,name=source_security_id,json=sourceSecurityId" json:"source_security_id,omitempty"`
	// These fields record the original source and destination addresses,
	// stored in ipv4:port or [ipv6]:port format.
	SourceAddress      string `protobuf:"bytes,7,opt,name=source_address,json=sourceAddress" json:"source_address,omitempty"`
	DestinationAddress string `protobuf:"bytes,8,opt,name=destination_address,json=destinationAddress" json:"destination_address,omitempty"`
	// Request info that is also retained for the response
	Scheme string `protobuf:"bytes,9,opt,name=scheme" json:"scheme,omitempty"`
	Host   string `protobuf:"bytes,10,opt,name=host" json:"host,omitempty"`
	Path   string `protobuf:"bytes,11,opt,name=path" json:"path,omitempty"`
	Method string `protobuf:"bytes,12,opt,name=method" json:"method,omitempty"`
	// Response info
	Status uint32 `protobuf:"varint,13,opt,name=status" json:"status,omitempty"`
	// Request headers not included above
	Headers []*KeyValue `protobuf:"bytes,14,rep,name=headers" json:"headers,omitempty"`
}

func (m *HttpLogEntry) Reset()                    { *m = HttpLogEntry{} }
func (m *HttpLogEntry) String() string            { return proto.CompactTextString(m) }
func (*HttpLogEntry) ProtoMessage()               {}
func (*HttpLogEntry) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *HttpLogEntry) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *HttpLogEntry) GetHttpProtocol() Protocol {
	if m != nil {
		return m.HttpProtocol
	}
	return Protocol_HTTP10
}

func (m *HttpLogEntry) GetEntryType() EntryType {
	if m != nil {
		return m.EntryType
	}
	return EntryType_Request
}

func (m *HttpLogEntry) GetCiliumResourceName() string {
	if m != nil {
		return m.CiliumResourceName
	}
	return ""
}

func (m *HttpLogEntry) GetCiliumRuleRef() string {
	if m != nil {
		return m.CiliumRuleRef
	}
	return ""
}

func (m *HttpLogEntry) GetSourceSecurityId() uint32 {
	if m != nil {
		return m.SourceSecurityId
	}
	return 0
}

func (m *HttpLogEntry) GetSourceAddress() string {
	if m != nil {
		return m.SourceAddress
	}
	return ""
}

func (m *HttpLogEntry) GetDestinationAddress() string {
	if m != nil {
		return m.DestinationAddress
	}
	return ""
}

func (m *HttpLogEntry) GetScheme() string {
	if m != nil {
		return m.Scheme
	}
	return ""
}

func (m *HttpLogEntry) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func (m *HttpLogEntry) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *HttpLogEntry) GetMethod() string {
	if m != nil {
		return m.Method
	}
	return ""
}

func (m *HttpLogEntry) GetStatus() uint32 {
	if m != nil {
		return m.Status
	}
	return 0
}

func (m *HttpLogEntry) GetHeaders() []*KeyValue {
	if m != nil {
		return m.Headers
	}
	return nil
}

func init() {
	proto.RegisterType((*KeyValue)(nil), "cilium.KeyValue")
	proto.RegisterType((*HttpLogEntry)(nil), "cilium.HttpLogEntry")
	proto.RegisterEnum("cilium.Protocol", Protocol_name, Protocol_value)
	proto.RegisterEnum("cilium.EntryType", EntryType_name, EntryType_value)
}

func init() { proto.RegisterFile("cilium/accesslog.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 446 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x52, 0xcd, 0x8a, 0xd4, 0x40,
	0x10, 0xde, 0xcc, 0x4f, 0x26, 0xa9, 0xf9, 0x31, 0x96, 0xcb, 0xd2, 0x07, 0x0f, 0xc3, 0x82, 0x32,
	0x0c, 0x3a, 0x3b, 0x3b, 0xe2, 0x03, 0x28, 0x0a, 0x2b, 0x8a, 0x2c, 0xed, 0xe0, 0xc1, 0x4b, 0x68,
	0x93, 0xda, 0x4d, 0x30, 0x49, 0xc7, 0x74, 0x47, 0xc8, 0x63, 0xf8, 0xc6, 0x92, 0xee, 0xce, 0x8c,
	0xb7, 0xaf, 0xbe, 0x9f, 0xea, 0x6a, 0xaa, 0xe0, 0x2a, 0xc9, 0x8b, 0xbc, 0x2d, 0x6f, 0x44, 0x92,
	0x90, 0x52, 0x85, 0x7c, 0xdc, 0xd5, 0x8d, 0xd4, 0x12, 0x7d, 0xcb, 0x5f, 0x1f, 0x20, 0xf8, 0x4c,
	0xdd, 0x77, 0x51, 0xb4, 0x84, 0x11, 0x8c, 0x7f, 0x51, 0xc7, 0xbc, 0xb5, 0xb7, 0x09, 0x79, 0x0f,
	0xf1, 0x12, 0xa6, 0x7f, 0x7a, 0x89, 0x8d, 0x0c, 0x67, 0x8b, 0xeb, 0xbf, 0x13, 0x58, 0xdc, 0x69,
	0x5d, 0x7f, 0x91, 0x8f, 0x1f, 0x2b, 0xdd, 0x74, 0xf8, 0x1c, 0x42, 0x9d, 0x97, 0xa4, 0xb4, 0x28,
	0x6b, 0x13, 0x9f, 0xf0, 0x33, 0x81, 0x6f, 0x61, 0x99, 0x69, 0x5d, 0xc7, 0xe6, 0xe1, 0x44, 0x16,
	0xa6, 0xd9, 0xea, 0x10, 0xed, 0xec, 0x08, 0xbb, 0x7b, 0xc7, 0xf3, 0x45, 0x6f, 0x1b, 0x2a, 0xdc,
	0x03, 0x50, 0xdf, 0x3d, 0xd6, 0x5d, 0x4d, 0x6c, 0x6c, 0x32, 0x4f, 0x87, 0x8c, 0x79, 0xf7, 0xd8,
	0xd5, 0xc4, 0x43, 0x1a, 0x20, 0xee, 0xe1, 0xd2, 0xca, 0x71, 0x43, 0x4a, 0xb6, 0x4d, 0x42, 0x71,
	0x25, 0x4a, 0x62, 0x13, 0x33, 0x3c, 0x5a, 0x8d, 0x3b, 0xe9, 0xab, 0x28, 0x09, 0x5f, 0xc2, 0x93,
	0x21, 0xd1, 0x16, 0x14, 0x37, 0xf4, 0xc0, 0xa6, 0xc6, 0xbc, 0x74, 0xe6, 0xb6, 0x20, 0x4e, 0x0f,
	0xf8, 0x0a, 0xd0, 0x35, 0x54, 0x94, 0xb4, 0x4d, 0xae, 0xbb, 0x38, 0x4f, 0x99, 0xbf, 0xf6, 0x36,
	0x4b, 0x1e, 0x59, 0xe5, 0x9b, 0x13, 0x3e, 0xa5, 0xf8, 0x02, 0x56, 0xce, 0x2d, 0xd2, 0xb4, 0x21,
	0xa5, 0xd8, 0xcc, 0x36, 0xb5, 0xec, 0x3b, 0x4b, 0xe2, 0x0d, 0x3c, 0x4b, 0x49, 0xe9, 0xbc, 0x12,
	0x3a, 0x97, 0xd5, 0xc9, 0x1b, 0xd8, 0x69, 0xff, 0x93, 0x86, 0xc0, 0x15, 0xf8, 0x2a, 0xc9, 0xa8,
	0x24, 0x16, 0x1a, 0x8f, 0xab, 0x10, 0x61, 0x92, 0x49, 0xa5, 0x19, 0x18, 0xd6, 0xe0, 0x9e, 0xab,
	0x85, 0xce, 0xd8, 0xdc, 0x72, 0x3d, 0xee, 0xf3, 0x25, 0xe9, 0x4c, 0xa6, 0x6c, 0x61, 0xf3, 0xb6,
	0x32, 0x7d, 0xb5, 0xd0, 0xad, 0x62, 0x4b, 0xf3, 0x23, 0x57, 0xe1, 0x16, 0x66, 0x19, 0x89, 0x94,
	0x1a, 0xc5, 0x56, 0xeb, 0xf1, 0x66, 0x7e, 0x5e, 0xd9, 0x70, 0x32, 0x7c, 0x30, 0x6c, 0x5f, 0x43,
	0x70, 0xda, 0x1c, 0x80, 0x7f, 0x77, 0x3c, 0xde, 0xdf, 0xee, 0xa3, 0x8b, 0x13, 0xbe, 0x8d, 0x3c,
	0x0c, 0x61, 0xda, 0xe3, 0x43, 0x34, 0xda, 0x1e, 0x20, 0x3c, 0xad, 0x10, 0xe7, 0x30, 0xe3, 0xf4,
	0xbb, 0x25, 0xa5, 0xa3, 0x0b, 0x5c, 0x40, 0xc0, 0x49, 0xd5, 0xb2, 0x52, 0x14, 0x79, 0x7d, 0xfc,
	0x03, 0x55, 0x39, 0xa5, 0xd1, 0xe8, 0x7d, 0xf0, 0xc3, 0x1d, 0xed, 0x4f, 0xdf, 0x9c, 0xd2, 0x9b,
	0x7f, 0x01, 0x00, 0x00, 0xff, 0xff, 0xcf, 0x57, 0xd0, 0x07, 0xdd, 0x02, 0x00, 0x00,
}
