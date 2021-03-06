// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/filter/network/tcp_proxy/v2/tcp_proxy.proto

/*
Package v2 is a generated protocol buffer package.

It is generated from these files:
	envoy/config/filter/network/tcp_proxy/v2/tcp_proxy.proto

It has these top-level messages:
	TcpProxy
*/
package v2

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import envoy_config_filter_accesslog_v2 "github.com/cilium/cilium/pkg/envoy/envoy/config/filter/accesslog/v2"
import envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
import google_protobuf2 "github.com/golang/protobuf/ptypes/duration"
import google_protobuf "github.com/golang/protobuf/ptypes/wrappers"
import _ "github.com/lyft/protoc-gen-validate/validate"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type TcpProxy struct {
	// The prefix to use when emitting :ref:`statistics
	// <config_network_filters_tcp_proxy_stats>`.
	StatPrefix string `protobuf:"bytes,1,opt,name=stat_prefix,json=statPrefix" json:"stat_prefix,omitempty"`
	// The upstream cluster to connect to.
	//
	// .. note::
	//
	//  Once full filter chain matching is implemented in listeners, this field will become the only
	//  way to configure the target cluster. All other matching will be done via :ref:`filter chain
	//  matching rules <envoy_api_msg_listener.FilterChainMatch>`. For very simple configurations,
	//  this field can still be used to select the cluster when no other matching rules are required.
	//  Otherwise, a :ref:`deprecated_v1
	//  <envoy_api_field_config.filter.network.tcp_proxy.v2.TcpProxy.deprecated_v1>` configuration is
	//  required to use more complex routing in the interim.
	//
	Cluster string `protobuf:"bytes,2,opt,name=cluster" json:"cluster,omitempty"`
	// The idle timeout for connections managed by the TCP proxy filter. The idle timeout
	// is defined as the period in which there are no bytes sent or received on either
	// the upstream or downstream connection. If not set, connections will never be closed
	// by the TCP proxy due to being idle.
	IdleTimeout *google_protobuf2.Duration `protobuf:"bytes,8,opt,name=idle_timeout,json=idleTimeout" json:"idle_timeout,omitempty"`
	// [#not-implemented-hide:] The idle timeout for connections managed by the TCP proxy
	// filter. The idle timeout is defined as the period in which there is no
	// active traffic. If not set, there is no idle timeout. When the idle timeout
	// is reached the connection will be closed. The distinction between
	// downstream_idle_timeout/upstream_idle_timeout provides a means to set
	// timeout based on the last byte sent on the downstream/upstream connection.
	DownstreamIdleTimeout *google_protobuf2.Duration `protobuf:"bytes,3,opt,name=downstream_idle_timeout,json=downstreamIdleTimeout" json:"downstream_idle_timeout,omitempty"`
	// [#not-implemented-hide:]
	UpstreamIdleTimeout *google_protobuf2.Duration `protobuf:"bytes,4,opt,name=upstream_idle_timeout,json=upstreamIdleTimeout" json:"upstream_idle_timeout,omitempty"`
	// Configuration for :ref:`access logs <arch_overview_access_logs>`
	// emitted by the this tcp_proxy.
	AccessLog []*envoy_config_filter_accesslog_v2.AccessLog `protobuf:"bytes,5,rep,name=access_log,json=accessLog" json:"access_log,omitempty"`
	// TCP Proxy filter configuration using deprecated V1 format. This is required for complex
	// routing until filter chain matching in the listener is implemented.
	//
	// .. attention::
	//
	//   Using this field will lead to `problems loading the configuration
	//   <https://github.com/envoyproxy/envoy/issues/2441>`_. If you
	//   want to configure the filter using v1 config structure, please make this
	//   field a boolean with value ``true`` and configure via the opaque ``value`` field
	//   like is suggested in the filter `README
	//   <https://github.com/envoyproxy/data-plane-api/blob/master/envoy/api/v2/filter/README.md>`_.
	DeprecatedV1 *TcpProxy_DeprecatedV1 `protobuf:"bytes,6,opt,name=deprecated_v1,json=deprecatedV1" json:"deprecated_v1,omitempty"`
	// The maximum number of unsuccessful connection attempts that will be made before
	// giving up. If the parameter is not specified, 1 connection attempt will be made.
	MaxConnectAttempts *google_protobuf.UInt32Value `protobuf:"bytes,7,opt,name=max_connect_attempts,json=maxConnectAttempts" json:"max_connect_attempts,omitempty"`
}

func (m *TcpProxy) Reset()                    { *m = TcpProxy{} }
func (m *TcpProxy) String() string            { return proto.CompactTextString(m) }
func (*TcpProxy) ProtoMessage()               {}
func (*TcpProxy) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *TcpProxy) GetStatPrefix() string {
	if m != nil {
		return m.StatPrefix
	}
	return ""
}

func (m *TcpProxy) GetCluster() string {
	if m != nil {
		return m.Cluster
	}
	return ""
}

func (m *TcpProxy) GetIdleTimeout() *google_protobuf2.Duration {
	if m != nil {
		return m.IdleTimeout
	}
	return nil
}

func (m *TcpProxy) GetDownstreamIdleTimeout() *google_protobuf2.Duration {
	if m != nil {
		return m.DownstreamIdleTimeout
	}
	return nil
}

func (m *TcpProxy) GetUpstreamIdleTimeout() *google_protobuf2.Duration {
	if m != nil {
		return m.UpstreamIdleTimeout
	}
	return nil
}

func (m *TcpProxy) GetAccessLog() []*envoy_config_filter_accesslog_v2.AccessLog {
	if m != nil {
		return m.AccessLog
	}
	return nil
}

func (m *TcpProxy) GetDeprecatedV1() *TcpProxy_DeprecatedV1 {
	if m != nil {
		return m.DeprecatedV1
	}
	return nil
}

func (m *TcpProxy) GetMaxConnectAttempts() *google_protobuf.UInt32Value {
	if m != nil {
		return m.MaxConnectAttempts
	}
	return nil
}

// TCP Proxy filter configuration using V1 format, until Envoy gets the
// ability to match source/destination at the listener level (called
// :ref:`filter chain match <envoy_api_msg_listener.FilterChainMatch>`).
type TcpProxy_DeprecatedV1 struct {
	// The route table for the filter. All filter instances must have a route
	// table, even if it is empty.
	Routes []*TcpProxy_DeprecatedV1_TCPRoute `protobuf:"bytes,1,rep,name=routes" json:"routes,omitempty"`
}

func (m *TcpProxy_DeprecatedV1) Reset()                    { *m = TcpProxy_DeprecatedV1{} }
func (m *TcpProxy_DeprecatedV1) String() string            { return proto.CompactTextString(m) }
func (*TcpProxy_DeprecatedV1) ProtoMessage()               {}
func (*TcpProxy_DeprecatedV1) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 0} }

func (m *TcpProxy_DeprecatedV1) GetRoutes() []*TcpProxy_DeprecatedV1_TCPRoute {
	if m != nil {
		return m.Routes
	}
	return nil
}

// A TCP proxy route consists of a set of optional L4 criteria and the
// name of a cluster. If a downstream connection matches all the
// specified criteria, the cluster in the route is used for the
// corresponding upstream connection. Routes are tried in the order
// specified until a match is found. If no match is found, the connection
// is closed. A route with no criteria is valid and always produces a
// match.
type TcpProxy_DeprecatedV1_TCPRoute struct {
	// The cluster to connect to when a the downstream network connection
	// matches the specified criteria.
	Cluster string `protobuf:"bytes,1,opt,name=cluster" json:"cluster,omitempty"`
	// An optional list of IP address subnets in the form
	// “ip_address/xx”. The criteria is satisfied if the destination IP
	// address of the downstream connection is contained in at least one of
	// the specified subnets. If the parameter is not specified or the list
	// is empty, the destination IP address is ignored. The destination IP
	// address of the downstream connection might be different from the
	// addresses on which the proxy is listening if the connection has been
	// redirected.
	DestinationIpList []*envoy_api_v2_core.CidrRange `protobuf:"bytes,2,rep,name=destination_ip_list,json=destinationIpList" json:"destination_ip_list,omitempty"`
	// An optional string containing a comma-separated list of port numbers
	// or ranges. The criteria is satisfied if the destination port of the
	// downstream connection is contained in at least one of the specified
	// ranges. If the parameter is not specified, the destination port is
	// ignored. The destination port address of the downstream connection
	// might be different from the port on which the proxy is listening if
	// the connection has been redirected.
	DestinationPorts string `protobuf:"bytes,3,opt,name=destination_ports,json=destinationPorts" json:"destination_ports,omitempty"`
	// An optional list of IP address subnets in the form
	// “ip_address/xx”. The criteria is satisfied if the source IP address
	// of the downstream connection is contained in at least one of the
	// specified subnets. If the parameter is not specified or the list is
	// empty, the source IP address is ignored.
	SourceIpList []*envoy_api_v2_core.CidrRange `protobuf:"bytes,4,rep,name=source_ip_list,json=sourceIpList" json:"source_ip_list,omitempty"`
	// An optional string containing a comma-separated list of port numbers
	// or ranges. The criteria is satisfied if the source port of the
	// downstream connection is contained in at least one of the specified
	// ranges. If the parameter is not specified, the source port is
	// ignored.
	SourcePorts string `protobuf:"bytes,5,opt,name=source_ports,json=sourcePorts" json:"source_ports,omitempty"`
}

func (m *TcpProxy_DeprecatedV1_TCPRoute) Reset()         { *m = TcpProxy_DeprecatedV1_TCPRoute{} }
func (m *TcpProxy_DeprecatedV1_TCPRoute) String() string { return proto.CompactTextString(m) }
func (*TcpProxy_DeprecatedV1_TCPRoute) ProtoMessage()    {}
func (*TcpProxy_DeprecatedV1_TCPRoute) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{0, 0, 0}
}

func (m *TcpProxy_DeprecatedV1_TCPRoute) GetCluster() string {
	if m != nil {
		return m.Cluster
	}
	return ""
}

func (m *TcpProxy_DeprecatedV1_TCPRoute) GetDestinationIpList() []*envoy_api_v2_core.CidrRange {
	if m != nil {
		return m.DestinationIpList
	}
	return nil
}

func (m *TcpProxy_DeprecatedV1_TCPRoute) GetDestinationPorts() string {
	if m != nil {
		return m.DestinationPorts
	}
	return ""
}

func (m *TcpProxy_DeprecatedV1_TCPRoute) GetSourceIpList() []*envoy_api_v2_core.CidrRange {
	if m != nil {
		return m.SourceIpList
	}
	return nil
}

func (m *TcpProxy_DeprecatedV1_TCPRoute) GetSourcePorts() string {
	if m != nil {
		return m.SourcePorts
	}
	return ""
}

func init() {
	proto.RegisterType((*TcpProxy)(nil), "envoy.config.filter.network.tcp_proxy.v2.TcpProxy")
	proto.RegisterType((*TcpProxy_DeprecatedV1)(nil), "envoy.config.filter.network.tcp_proxy.v2.TcpProxy.DeprecatedV1")
	proto.RegisterType((*TcpProxy_DeprecatedV1_TCPRoute)(nil), "envoy.config.filter.network.tcp_proxy.v2.TcpProxy.DeprecatedV1.TCPRoute")
}

func init() {
	proto.RegisterFile("envoy/config/filter/network/tcp_proxy/v2/tcp_proxy.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 626 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x53, 0xcd, 0x6e, 0xd3, 0x4c,
	0x14, 0xfd, 0xec, 0xa4, 0x6d, 0x32, 0xc9, 0x57, 0x81, 0xdb, 0xaa, 0x26, 0xaa, 0x68, 0x80, 0x4d,
	0xd4, 0x4a, 0x63, 0xea, 0x6e, 0xd8, 0xa1, 0xa6, 0x5d, 0x50, 0x54, 0xa4, 0x60, 0x95, 0x4a, 0xb0,
	0xb1, 0xa6, 0xf6, 0x8d, 0x19, 0xe1, 0x78, 0x46, 0x33, 0x63, 0x37, 0x7d, 0x0b, 0x60, 0xc5, 0x33,
	0xf0, 0x08, 0xac, 0x78, 0x13, 0x36, 0x6c, 0x78, 0x0b, 0x34, 0x63, 0xbb, 0x31, 0x6a, 0x51, 0x2b,
	0xb1, 0xbb, 0x7f, 0xe7, 0x9c, 0x3b, 0xbe, 0xc7, 0xe8, 0x19, 0x64, 0x05, 0xbb, 0xf4, 0x22, 0x96,
	0x4d, 0x69, 0xe2, 0x4d, 0x69, 0xaa, 0x40, 0x78, 0x19, 0xa8, 0x0b, 0x26, 0x3e, 0x78, 0x2a, 0xe2,
	0x21, 0x17, 0x6c, 0x7e, 0xe9, 0x15, 0xfe, 0x22, 0xc1, 0x5c, 0x30, 0xc5, 0x9c, 0x91, 0x41, 0xe2,
	0x12, 0x89, 0x4b, 0x24, 0xae, 0x90, 0x78, 0x31, 0x5c, 0xf8, 0x83, 0xa7, 0x37, 0x69, 0x90, 0x28,
	0x02, 0x29, 0x53, 0x96, 0x68, 0xee, 0xab, 0xa4, 0xe4, 0x1e, 0x6c, 0x97, 0x08, 0xc2, 0xa9, 0xee,
	0x46, 0x4c, 0x80, 0x47, 0xe2, 0x58, 0x80, 0x94, 0xd5, 0xc0, 0xc3, 0x84, 0xb1, 0x24, 0x05, 0xcf,
	0x64, 0xe7, 0xf9, 0xd4, 0x8b, 0x73, 0x41, 0x14, 0x65, 0xd9, 0xdf, 0xfa, 0x17, 0x82, 0x70, 0x0e,
	0xa2, 0xc6, 0x6f, 0x16, 0x24, 0xa5, 0x31, 0x51, 0xe0, 0xd5, 0x41, 0xd5, 0x58, 0x4f, 0x58, 0xc2,
	0x4c, 0xe8, 0xe9, 0xa8, 0xac, 0x3e, 0xfe, 0xb9, 0x82, 0x3a, 0xa7, 0x11, 0x9f, 0xe8, 0x17, 0x39,
	0x3b, 0xa8, 0x27, 0x15, 0x51, 0x21, 0x17, 0x30, 0xa5, 0x73, 0xd7, 0x1a, 0x5a, 0xa3, 0xee, 0xb8,
	0xfb, 0xed, 0xd7, 0xf7, 0x56, 0x5b, 0xd8, 0x43, 0x2b, 0x40, 0xba, 0x3b, 0x31, 0x4d, 0xc7, 0x45,
	0x2b, 0x51, 0x9a, 0x4b, 0x05, 0xc2, 0xb5, 0xf5, 0x5c, 0x50, 0xa7, 0xce, 0x09, 0xea, 0xd3, 0x38,
	0x85, 0x50, 0xd1, 0x19, 0xb0, 0x5c, 0xb9, 0x9d, 0xa1, 0x35, 0xea, 0xf9, 0x0f, 0x70, 0xb9, 0x38,
	0xae, 0x17, 0xc7, 0x47, 0xd5, 0xc3, 0xc6, 0xab, 0x5f, 0x7e, 0x6c, 0x5b, 0x5a, 0x65, 0xe9, 0xab,
	0x65, 0xef, 0xfc, 0x17, 0xf4, 0x34, 0xfc, 0xb4, 0x44, 0x3b, 0xaf, 0xd1, 0x66, 0xcc, 0x2e, 0x32,
	0xa9, 0x04, 0x90, 0x59, 0xf8, 0x07, 0x71, 0xeb, 0x16, 0xe2, 0x60, 0x63, 0x81, 0x3c, 0x6e, 0x50,
	0xbe, 0x42, 0x1b, 0x39, 0xbf, 0x89, 0xb0, 0x7d, 0x1b, 0xe1, 0x5a, 0x8d, 0x6b, 0xd2, 0xbd, 0x44,
	0xa8, 0xbc, 0x72, 0x98, 0xb2, 0xc4, 0x5d, 0x1a, 0xb6, 0x46, 0x3d, 0x7f, 0x17, 0xdf, 0xe4, 0xa1,
	0x85, 0x19, 0x0a, 0x1f, 0x1f, 0x98, 0xe4, 0x84, 0x25, 0x41, 0x97, 0xd4, 0xa1, 0xf3, 0x1e, 0xfd,
	0x1f, 0x03, 0x17, 0x10, 0x11, 0x05, 0x71, 0x58, 0xec, 0xb9, 0xcb, 0x66, 0xa5, 0xe7, 0xf8, 0xae,
	0x96, 0xc4, 0xf5, 0x31, 0xf1, 0xd1, 0x15, 0xcf, 0xd9, 0xde, 0xd8, 0x76, 0xad, 0xa0, 0x1f, 0x37,
	0x2a, 0xce, 0x5b, 0xb4, 0x3e, 0x23, 0xf3, 0x30, 0x62, 0x59, 0x06, 0x91, 0x0a, 0x89, 0x52, 0x30,
	0xe3, 0x4a, 0xba, 0x2b, 0x46, 0x70, 0xeb, 0xda, 0x37, 0x78, 0x73, 0x9c, 0xa9, 0x7d, 0xff, 0x8c,
	0xa4, 0x39, 0x54, 0x96, 0xd8, 0xb1, 0x47, 0x56, 0xe0, 0xcc, 0xc8, 0xfc, 0xb0, 0xe4, 0x38, 0xa8,
	0x28, 0x06, 0x1f, 0x5b, 0xa8, 0xdf, 0x54, 0x77, 0x52, 0xb4, 0x2c, 0x58, 0xae, 0x40, 0xba, 0x96,
	0xf9, 0x3a, 0x2f, 0xfe, 0xf1, 0x39, 0xf8, 0xf4, 0x70, 0x12, 0x68, 0xc2, 0x31, 0x32, 0xb6, 0xf9,
	0x6c, 0xd9, 0x1d, 0x2b, 0xa8, 0x34, 0x06, 0x9f, 0x6c, 0xd4, 0xa9, 0x07, 0x9c, 0x27, 0x0b, 0x9b,
	0x5e, 0xb3, 0x73, 0xc3, 0xb1, 0x6b, 0x31, 0x48, 0x45, 0x33, 0x73, 0xe5, 0x90, 0xf2, 0x30, 0xa5,
	0x52, 0xb9, 0xb6, 0x59, 0x76, 0xab, 0x5a, 0x96, 0x70, 0xaa, 0x17, 0xd2, 0xbf, 0x2c, 0x3e, 0xa4,
	0xb1, 0x08, 0x48, 0x96, 0x40, 0x70, 0xbf, 0x01, 0x3c, 0xe6, 0x27, 0x54, 0x2a, 0x67, 0x17, 0x35,
	0x8b, 0x21, 0x67, 0x42, 0x49, 0xe3, 0xd5, 0x6e, 0x70, 0xaf, 0xd1, 0x98, 0xe8, 0xba, 0x33, 0x46,
	0xab, 0x92, 0xe5, 0x22, 0x82, 0x2b, 0xd5, 0xf6, 0x1d, 0x54, 0xfb, 0x25, 0xa6, 0x12, 0x7c, 0x84,
	0xaa, 0xbc, 0xd2, 0x5a, 0x32, 0x5a, 0xbd, 0xb2, 0x66, 0x64, 0xc6, 0xed, 0x77, 0x76, 0xe1, 0x9f,
	0x2f, 0x9b, 0x6b, 0xee, 0xff, 0x0e, 0x00, 0x00, 0xff, 0xff, 0x6d, 0xa9, 0x72, 0xd1, 0x1b, 0x05,
	0x00, 0x00,
}
