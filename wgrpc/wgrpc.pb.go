// Code generated by protoc-gen-go. DO NOT EDIT.
// source: wgrpc.proto

package wgrpc

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

type StatusRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StatusRequest) Reset()         { *m = StatusRequest{} }
func (m *StatusRequest) String() string { return proto.CompactTextString(m) }
func (*StatusRequest) ProtoMessage()    {}
func (*StatusRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2fb1742ce9418ce3, []int{0}
}

func (m *StatusRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StatusRequest.Unmarshal(m, b)
}
func (m *StatusRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StatusRequest.Marshal(b, m, deterministic)
}
func (m *StatusRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StatusRequest.Merge(m, src)
}
func (m *StatusRequest) XXX_Size() int {
	return xxx_messageInfo_StatusRequest.Size(m)
}
func (m *StatusRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StatusRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StatusRequest proto.InternalMessageInfo

type StatusReply struct {
	Status               string   `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	LastError            string   `protobuf:"bytes,2,opt,name=lastError,proto3" json:"lastError,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StatusReply) Reset()         { *m = StatusReply{} }
func (m *StatusReply) String() string { return proto.CompactTextString(m) }
func (*StatusReply) ProtoMessage()    {}
func (*StatusReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_2fb1742ce9418ce3, []int{1}
}

func (m *StatusReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StatusReply.Unmarshal(m, b)
}
func (m *StatusReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StatusReply.Marshal(b, m, deterministic)
}
func (m *StatusReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StatusReply.Merge(m, src)
}
func (m *StatusReply) XXX_Size() int {
	return xxx_messageInfo_StatusReply.Size(m)
}
func (m *StatusReply) XXX_DiscardUnknown() {
	xxx_messageInfo_StatusReply.DiscardUnknown(m)
}

var xxx_messageInfo_StatusReply proto.InternalMessageInfo

func (m *StatusReply) GetStatus() string {
	if m != nil {
		return m.Status
	}
	return ""
}

func (m *StatusReply) GetLastError() string {
	if m != nil {
		return m.LastError
	}
	return ""
}

func init() {
	proto.RegisterType((*StatusRequest)(nil), "StatusRequest")
	proto.RegisterType((*StatusReply)(nil), "StatusReply")
}

func init() {
	proto.RegisterFile("wgrpc.proto", fileDescriptor_2fb1742ce9418ce3)
}

var fileDescriptor_2fb1742ce9418ce3 = []byte{
	// 143 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xe2, 0x2e, 0x4f, 0x2f, 0x2a,
	0x48, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x57, 0xe2, 0xe7, 0xe2, 0x0d, 0x2e, 0x49, 0x2c, 0x29,
	0x2d, 0x0e, 0x4a, 0x2d, 0x2c, 0x4d, 0x2d, 0x2e, 0x51, 0x72, 0xe6, 0xe2, 0x86, 0x09, 0x14, 0xe4,
	0x54, 0x0a, 0x89, 0x71, 0xb1, 0x15, 0x83, 0xb9, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x9c, 0x41, 0x50,
	0x9e, 0x90, 0x0c, 0x17, 0x67, 0x4e, 0x62, 0x71, 0x89, 0x6b, 0x51, 0x51, 0x7e, 0x91, 0x04, 0x13,
	0x58, 0x0a, 0x21, 0x60, 0x64, 0xc1, 0xc5, 0x19, 0xee, 0x1e, 0x9c, 0x5a, 0x54, 0x96, 0x99, 0x9c,
	0x2a, 0xa4, 0xcd, 0xc5, 0xe9, 0x9e, 0x5a, 0x02, 0x31, 0x54, 0x88, 0x4f, 0x0f, 0xc5, 0x3a, 0x29,
	0x1e, 0x3d, 0x24, 0xdb, 0x94, 0x18, 0x9c, 0xd8, 0xa3, 0x58, 0xc1, 0xce, 0x4b, 0x62, 0x03, 0xbb,
	0xcf, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff, 0x38, 0xf4, 0x8b, 0x1f, 0xae, 0x00, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// WGServiceClient is the client API for WGService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type WGServiceClient interface {
	GetStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusReply, error)
}

type wGServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewWGServiceClient(cc grpc.ClientConnInterface) WGServiceClient {
	return &wGServiceClient{cc}
}

func (c *wGServiceClient) GetStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusReply, error) {
	out := new(StatusReply)
	err := c.cc.Invoke(ctx, "/WGService/GetStatus", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WGServiceServer is the server API for WGService service.
type WGServiceServer interface {
	GetStatus(context.Context, *StatusRequest) (*StatusReply, error)
}

// UnimplementedWGServiceServer can be embedded to have forward compatible implementations.
type UnimplementedWGServiceServer struct {
}

func (*UnimplementedWGServiceServer) GetStatus(ctx context.Context, req *StatusRequest) (*StatusReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStatus not implemented")
}

func RegisterWGServiceServer(s *grpc.Server, srv WGServiceServer) {
	s.RegisterService(&_WGService_serviceDesc, srv)
}

func _WGService_GetStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WGServiceServer).GetStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/WGService/GetStatus",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WGServiceServer).GetStatus(ctx, req.(*StatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _WGService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "WGService",
	HandlerType: (*WGServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetStatus",
			Handler:    _WGService_GetStatus_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "wgrpc.proto",
}