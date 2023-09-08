// Code generated by MockGen. DO NOT EDIT.
// Source: nodenetsvc_grpc.pb.go

// Package nodenetsvc_v1_mock is a generated GoMock package.
package nodenetsvc_v1_mock

import (
	context "context"
	reflect "reflect"

	v1 "github.com/Microsoft/hcsshim/pkg/ncproxy/nodenetsvc/v1"
	gomock "go.uber.org/mock/gomock"
	grpc "google.golang.org/grpc"
)

// MockNodeNetworkServiceClient is a mock of NodeNetworkServiceClient interface.
type MockNodeNetworkServiceClient struct {
	ctrl     *gomock.Controller
	recorder *MockNodeNetworkServiceClientMockRecorder
}

// MockNodeNetworkServiceClientMockRecorder is the mock recorder for MockNodeNetworkServiceClient.
type MockNodeNetworkServiceClientMockRecorder struct {
	mock *MockNodeNetworkServiceClient
}

// NewMockNodeNetworkServiceClient creates a new mock instance.
func NewMockNodeNetworkServiceClient(ctrl *gomock.Controller) *MockNodeNetworkServiceClient {
	mock := &MockNodeNetworkServiceClient{ctrl: ctrl}
	mock.recorder = &MockNodeNetworkServiceClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNodeNetworkServiceClient) EXPECT() *MockNodeNetworkServiceClientMockRecorder {
	return m.recorder
}

// ConfigureContainerNetworking mocks base method.
func (m *MockNodeNetworkServiceClient) ConfigureContainerNetworking(ctx context.Context, in *v1.ConfigureContainerNetworkingRequest, opts ...grpc.CallOption) (*v1.ConfigureContainerNetworkingResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ConfigureContainerNetworking", varargs...)
	ret0, _ := ret[0].(*v1.ConfigureContainerNetworkingResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConfigureContainerNetworking indicates an expected call of ConfigureContainerNetworking.
func (mr *MockNodeNetworkServiceClientMockRecorder) ConfigureContainerNetworking(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigureContainerNetworking", reflect.TypeOf((*MockNodeNetworkServiceClient)(nil).ConfigureContainerNetworking), varargs...)
}

// ConfigureNetworking mocks base method.
func (m *MockNodeNetworkServiceClient) ConfigureNetworking(ctx context.Context, in *v1.ConfigureNetworkingRequest, opts ...grpc.CallOption) (*v1.ConfigureNetworkingResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ConfigureNetworking", varargs...)
	ret0, _ := ret[0].(*v1.ConfigureNetworkingResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConfigureNetworking indicates an expected call of ConfigureNetworking.
func (mr *MockNodeNetworkServiceClientMockRecorder) ConfigureNetworking(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigureNetworking", reflect.TypeOf((*MockNodeNetworkServiceClient)(nil).ConfigureNetworking), varargs...)
}

// GetHostLocalIpAddress mocks base method.
func (m *MockNodeNetworkServiceClient) GetHostLocalIpAddress(ctx context.Context, in *v1.GetHostLocalIpAddressRequest, opts ...grpc.CallOption) (*v1.GetHostLocalIpAddressResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetHostLocalIpAddress", varargs...)
	ret0, _ := ret[0].(*v1.GetHostLocalIpAddressResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetHostLocalIpAddress indicates an expected call of GetHostLocalIpAddress.
func (mr *MockNodeNetworkServiceClientMockRecorder) GetHostLocalIpAddress(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHostLocalIpAddress", reflect.TypeOf((*MockNodeNetworkServiceClient)(nil).GetHostLocalIpAddress), varargs...)
}

// PingNodeNetworkService mocks base method.
func (m *MockNodeNetworkServiceClient) PingNodeNetworkService(ctx context.Context, in *v1.PingNodeNetworkServiceRequest, opts ...grpc.CallOption) (*v1.PingNodeNetworkServiceResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "PingNodeNetworkService", varargs...)
	ret0, _ := ret[0].(*v1.PingNodeNetworkServiceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PingNodeNetworkService indicates an expected call of PingNodeNetworkService.
func (mr *MockNodeNetworkServiceClientMockRecorder) PingNodeNetworkService(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PingNodeNetworkService", reflect.TypeOf((*MockNodeNetworkServiceClient)(nil).PingNodeNetworkService), varargs...)
}

// MockNodeNetworkServiceServer is a mock of NodeNetworkServiceServer interface.
type MockNodeNetworkServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockNodeNetworkServiceServerMockRecorder
}

// MockNodeNetworkServiceServerMockRecorder is the mock recorder for MockNodeNetworkServiceServer.
type MockNodeNetworkServiceServerMockRecorder struct {
	mock *MockNodeNetworkServiceServer
}

// NewMockNodeNetworkServiceServer creates a new mock instance.
func NewMockNodeNetworkServiceServer(ctrl *gomock.Controller) *MockNodeNetworkServiceServer {
	mock := &MockNodeNetworkServiceServer{ctrl: ctrl}
	mock.recorder = &MockNodeNetworkServiceServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNodeNetworkServiceServer) EXPECT() *MockNodeNetworkServiceServerMockRecorder {
	return m.recorder
}

// ConfigureContainerNetworking mocks base method.
func (m *MockNodeNetworkServiceServer) ConfigureContainerNetworking(arg0 context.Context, arg1 *v1.ConfigureContainerNetworkingRequest) (*v1.ConfigureContainerNetworkingResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfigureContainerNetworking", arg0, arg1)
	ret0, _ := ret[0].(*v1.ConfigureContainerNetworkingResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConfigureContainerNetworking indicates an expected call of ConfigureContainerNetworking.
func (mr *MockNodeNetworkServiceServerMockRecorder) ConfigureContainerNetworking(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigureContainerNetworking", reflect.TypeOf((*MockNodeNetworkServiceServer)(nil).ConfigureContainerNetworking), arg0, arg1)
}

// ConfigureNetworking mocks base method.
func (m *MockNodeNetworkServiceServer) ConfigureNetworking(arg0 context.Context, arg1 *v1.ConfigureNetworkingRequest) (*v1.ConfigureNetworkingResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfigureNetworking", arg0, arg1)
	ret0, _ := ret[0].(*v1.ConfigureNetworkingResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConfigureNetworking indicates an expected call of ConfigureNetworking.
func (mr *MockNodeNetworkServiceServerMockRecorder) ConfigureNetworking(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigureNetworking", reflect.TypeOf((*MockNodeNetworkServiceServer)(nil).ConfigureNetworking), arg0, arg1)
}

// GetHostLocalIpAddress mocks base method.
func (m *MockNodeNetworkServiceServer) GetHostLocalIpAddress(arg0 context.Context, arg1 *v1.GetHostLocalIpAddressRequest) (*v1.GetHostLocalIpAddressResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHostLocalIpAddress", arg0, arg1)
	ret0, _ := ret[0].(*v1.GetHostLocalIpAddressResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetHostLocalIpAddress indicates an expected call of GetHostLocalIpAddress.
func (mr *MockNodeNetworkServiceServerMockRecorder) GetHostLocalIpAddress(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHostLocalIpAddress", reflect.TypeOf((*MockNodeNetworkServiceServer)(nil).GetHostLocalIpAddress), arg0, arg1)
}

// PingNodeNetworkService mocks base method.
func (m *MockNodeNetworkServiceServer) PingNodeNetworkService(arg0 context.Context, arg1 *v1.PingNodeNetworkServiceRequest) (*v1.PingNodeNetworkServiceResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PingNodeNetworkService", arg0, arg1)
	ret0, _ := ret[0].(*v1.PingNodeNetworkServiceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PingNodeNetworkService indicates an expected call of PingNodeNetworkService.
func (mr *MockNodeNetworkServiceServerMockRecorder) PingNodeNetworkService(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PingNodeNetworkService", reflect.TypeOf((*MockNodeNetworkServiceServer)(nil).PingNodeNetworkService), arg0, arg1)
}

// mustEmbedUnimplementedNodeNetworkServiceServer mocks base method.
func (m *MockNodeNetworkServiceServer) mustEmbedUnimplementedNodeNetworkServiceServer() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "mustEmbedUnimplementedNodeNetworkServiceServer")
}

// mustEmbedUnimplementedNodeNetworkServiceServer indicates an expected call of mustEmbedUnimplementedNodeNetworkServiceServer.
func (mr *MockNodeNetworkServiceServerMockRecorder) mustEmbedUnimplementedNodeNetworkServiceServer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "mustEmbedUnimplementedNodeNetworkServiceServer", reflect.TypeOf((*MockNodeNetworkServiceServer)(nil).mustEmbedUnimplementedNodeNetworkServiceServer))
}

// MockUnsafeNodeNetworkServiceServer is a mock of UnsafeNodeNetworkServiceServer interface.
type MockUnsafeNodeNetworkServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockUnsafeNodeNetworkServiceServerMockRecorder
}

// MockUnsafeNodeNetworkServiceServerMockRecorder is the mock recorder for MockUnsafeNodeNetworkServiceServer.
type MockUnsafeNodeNetworkServiceServerMockRecorder struct {
	mock *MockUnsafeNodeNetworkServiceServer
}

// NewMockUnsafeNodeNetworkServiceServer creates a new mock instance.
func NewMockUnsafeNodeNetworkServiceServer(ctrl *gomock.Controller) *MockUnsafeNodeNetworkServiceServer {
	mock := &MockUnsafeNodeNetworkServiceServer{ctrl: ctrl}
	mock.recorder = &MockUnsafeNodeNetworkServiceServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUnsafeNodeNetworkServiceServer) EXPECT() *MockUnsafeNodeNetworkServiceServerMockRecorder {
	return m.recorder
}

// mustEmbedUnimplementedNodeNetworkServiceServer mocks base method.
func (m *MockUnsafeNodeNetworkServiceServer) mustEmbedUnimplementedNodeNetworkServiceServer() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "mustEmbedUnimplementedNodeNetworkServiceServer")
}

// mustEmbedUnimplementedNodeNetworkServiceServer indicates an expected call of mustEmbedUnimplementedNodeNetworkServiceServer.
func (mr *MockUnsafeNodeNetworkServiceServerMockRecorder) mustEmbedUnimplementedNodeNetworkServiceServer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "mustEmbedUnimplementedNodeNetworkServiceServer", reflect.TypeOf((*MockUnsafeNodeNetworkServiceServer)(nil).mustEmbedUnimplementedNodeNetworkServiceServer))
}