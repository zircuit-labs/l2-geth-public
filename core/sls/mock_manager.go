// Code generated by MockGen. DO NOT EDIT.
// Source: manager.go

// Package sls is a generated GoMock package.
package sls

import (
	context "context"
	reflect "reflect"

	model "github.com/zircuit-labs/l2-geth-public/core/sls/model"
	types "github.com/zircuit-labs/l2-geth-public/core/types"
	gomock "github.com/golang/mock/gomock"
)

// MockDetectorManager is a mock of DetectorManager interface.
type MockDetectorManager struct {
	ctrl     *gomock.Controller
	recorder *MockDetectorManagerMockRecorder
}

// MockDetectorManagerMockRecorder is the mock recorder for MockDetectorManager.
type MockDetectorManagerMockRecorder struct {
	mock *MockDetectorManager
}

// NewMockDetectorManager creates a new mock instance.
func NewMockDetectorManager(ctrl *gomock.Controller) *MockDetectorManager {
	mock := &MockDetectorManager{ctrl: ctrl}
	mock.recorder = &MockDetectorManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDetectorManager) EXPECT() *MockDetectorManagerMockRecorder {
	return m.recorder
}

// ShouldBeQuarantined mocks base method.
func (m *MockDetectorManager) ShouldBeQuarantined(ctx context.Context, tx *types.Transaction) (ManagerResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ShouldBeQuarantined", ctx, tx)
	ret0, _ := ret[0].(ManagerResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ShouldBeQuarantined indicates an expected call of ShouldBeQuarantined.
func (mr *MockDetectorManagerMockRecorder) ShouldBeQuarantined(ctx, tx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ShouldBeQuarantined", reflect.TypeOf((*MockDetectorManager)(nil).ShouldBeQuarantined), ctx, tx)
}

// Stop mocks base method.
func (m *MockDetectorManager) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop.
func (mr *MockDetectorManagerMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockDetectorManager)(nil).Stop))
}

// MockDetector is a mock of Detector interface.
type MockDetector struct {
	ctrl     *gomock.Controller
	recorder *MockDetectorMockRecorder
}

// MockDetectorMockRecorder is the mock recorder for MockDetector.
type MockDetectorMockRecorder struct {
	mock *MockDetector
}

// NewMockDetector creates a new mock instance.
func NewMockDetector(ctrl *gomock.Controller) *MockDetector {
	mock := &MockDetector{ctrl: ctrl}
	mock.recorder = &MockDetectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDetector) EXPECT() *MockDetectorMockRecorder {
	return m.recorder
}

// Name mocks base method.
func (m *MockDetector) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockDetectorMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockDetector)(nil).Name))
}

// ShouldBeQuarantined mocks base method.
func (m *MockDetector) ShouldBeQuarantined(ctx context.Context, transaction *types.Transaction) (bool, string, uint64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ShouldBeQuarantined", ctx, transaction)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(uint64)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// ShouldBeQuarantined indicates an expected call of ShouldBeQuarantined.
func (mr *MockDetectorMockRecorder) ShouldBeQuarantined(ctx, transaction interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ShouldBeQuarantined", reflect.TypeOf((*MockDetector)(nil).ShouldBeQuarantined), ctx, transaction)
}

// Stop mocks base method.
func (m *MockDetector) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop.
func (mr *MockDetectorMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockDetector)(nil).Stop))
}

// MockTrustVerifier is a mock of TrustVerifier interface.
type MockTrustVerifier struct {
	ctrl     *gomock.Controller
	recorder *MockTrustVerifierMockRecorder
}

// MockTrustVerifierMockRecorder is the mock recorder for MockTrustVerifier.
type MockTrustVerifierMockRecorder struct {
	mock *MockTrustVerifier
}

// NewMockTrustVerifier creates a new mock instance.
func NewMockTrustVerifier(ctrl *gomock.Controller) *MockTrustVerifier {
	mock := &MockTrustVerifier{ctrl: ctrl}
	mock.recorder = &MockTrustVerifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTrustVerifier) EXPECT() *MockTrustVerifierMockRecorder {
	return m.recorder
}

// IsTrustable mocks base method.
func (m *MockTrustVerifier) IsTrustable(ctx context.Context, transaction *types.Transaction) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsTrustable", ctx, transaction)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsTrustable indicates an expected call of IsTrustable.
func (mr *MockTrustVerifierMockRecorder) IsTrustable(ctx, transaction interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsTrustable", reflect.TypeOf((*MockTrustVerifier)(nil).IsTrustable), ctx, transaction)
}

// Name mocks base method.
func (m *MockTrustVerifier) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockTrustVerifierMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockTrustVerifier)(nil).Name))
}

// MockDatabase is a mock of Database interface.
type MockDatabase struct {
	ctrl     *gomock.Controller
	recorder *MockDatabaseMockRecorder
}

// MockDatabaseMockRecorder is the mock recorder for MockDatabase.
type MockDatabaseMockRecorder struct {
	mock *MockDatabase
}

// NewMockDatabase creates a new mock instance.
func NewMockDatabase(ctrl *gomock.Controller) *MockDatabase {
	mock := &MockDatabase{ctrl: ctrl}
	mock.recorder = &MockDatabaseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDatabase) EXPECT() *MockDatabaseMockRecorder {
	return m.recorder
}

// AddTransactionResult mocks base method.
func (m *MockDatabase) AddTransactionResult(ctx context.Context, result *model.TransactionResult) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddTransactionResult", ctx, result)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddTransactionResult indicates an expected call of AddTransactionResult.
func (mr *MockDatabaseMockRecorder) AddTransactionResult(ctx, result interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddTransactionResult", reflect.TypeOf((*MockDatabase)(nil).AddTransactionResult), ctx, result)
}
