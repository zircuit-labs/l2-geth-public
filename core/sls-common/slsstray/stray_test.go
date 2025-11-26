package slsstray

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"go.uber.org/mock/gomock"
	"golang.org/x/sync/errgroup"
)

func TestGetStray(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name              string
		snapShotGenerator snapshotGenerator
		enableStray       bool
		enableSLSDataSync bool
		initialized       bool
		expectedErr       error
	}{
		{
			name:              "test error stray snapshot generator is nil",
			snapShotGenerator: nil,
			enableStray:       true,
			enableSLSDataSync: false,
			initialized:       true,
			expectedErr:       ErrNoSnapshotGenerator,
		},
		{
			name:              "test stray disabled",
			snapShotGenerator: NewMocksnapshotGenerator(ctrl),
			enableStray:       false,
			enableSLSDataSync: false,
			initialized:       false,
			expectedErr:       nil,
		},
		{
			name:              "test stray sequencer mode",
			snapShotGenerator: NewMocksnapshotGenerator(ctrl),
			enableStray:       true,
			enableSLSDataSync: false,
			initialized:       true,
			expectedErr:       nil,
		},
		{
			name:              "test error stray modes",
			snapShotGenerator: NewMocksnapshotGenerator(ctrl),
			enableStray:       true,
			enableSLSDataSync: true,
			initialized:       false,
			expectedErr:       ErrStrayModeConflict,
		},
		{
			name:              "test stray replica mode",
			snapShotGenerator: NewMocksnapshotGenerator(ctrl),
			enableStray:       false,
			enableSLSDataSync: true,
			initialized:       false,
			expectedErr:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stray, err := GetStray(t.Context(), nil, GetMode(tt.enableStray, tt.enableSLSDataSync), tt.snapShotGenerator, nil, nil)
			assert.ErrorIs(t, err, tt.expectedErr)
			if stray != nil {
				assert.Equal(t, defaultSnapshotIntervalLimit, stray.config.snapshotIntervalLimit)
			}
		})
	}
}

func TestNewDiffAndMetadata(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	testErr1 := errors.New("any1")
	testErr2 := errors.New("any2")

	tests := []struct {
		name        string
		mocks       func(*MockdiffGenerator, *MockmetadataGenerator, *MocksnapshotGenerator)
		data        any
		add         bool
		newSnapshot bool
		expectedErr error
	}{
		{
			name: "invoke RemoveDiffQuarantines on txHashes input",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).AnyTimes().Return(nil)
				diffGenMock.EXPECT().RemoveDiffQuarantines(gomock.Any()).Times(1).Return(nil)
				metaGenMock.EXPECT().NewMetadata().Times(1).Return(nil)
			},
			data:        []string{"hash1", "hash2"},
			expectedErr: nil,
		},
		{
			name: "invoke AddDiffQuarantines on quarantines input",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).AnyTimes().Return(nil)
				diffGenMock.EXPECT().AddDiffQuarantines(gomock.Any()).Times(1).Return(nil)
				metaGenMock.EXPECT().NewMetadata().Times(1).Return(nil)
			},
			data:        []*model.Quarantine{{}},
			expectedErr: nil,
		},
		{
			name: "invoke AddDiffAdmins on admins input",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).AnyTimes().Return(nil)
				diffGenMock.EXPECT().AddDiffAdmins(gomock.Any()).Times(1).Return(nil)
				metaGenMock.EXPECT().NewMetadata().Times(1).Return(nil)
			},
			data:        []slsCommon.ListItem{},
			add:         true,
			expectedErr: nil,
		},
		{
			name: "invoke RemoveDiffAdmins on admins input",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).AnyTimes().Return(nil)
				diffGenMock.EXPECT().RemoveDiffAdmins(gomock.Any()).Times(1).Return(nil)
				metaGenMock.EXPECT().NewMetadata().Times(1).Return(nil)
			},
			data:        []slsCommon.ListItem{{}},
			expectedErr: nil,
		},
		{
			name: "error in RemoveDiffQuarantines",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).AnyTimes().Return(nil)
				diffGenMock.EXPECT().RemoveDiffQuarantines(gomock.Any()).Times(1).Return(testErr1)
				metaGenMock.EXPECT().NewMetadata().Times(0).Return(nil)
			},
			data:        []string{"hash1", "hash2"},
			expectedErr: testErr1,
		},
		{
			name: "catch context error",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).AnyTimes().Return(nil)
				metaGenMock.EXPECT().NewMetadata().Times(1).DoAndReturn(func() error {
					time.Sleep(1 * time.Second)
					return nil
				})
			},
			data:        nil,
			expectedErr: t.Context().Err(),
		},
		{
			name: "errors in NewMetadata",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).AnyTimes().Return(nil)
				metaGenMock.EXPECT().NewMetadata().AnyTimes().Return(testErr2)
			},
			data:        nil,
			expectedErr: testErr2,
		},
		{
			name: "invoke TakeNewSnapshot",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).Times(1).Return(nil)
				metaGenMock.EXPECT().NewMetadata().AnyTimes().Return(nil)
			},
			data:        nil,
			newSnapshot: true,
			expectedErr: nil,
		},
		{
			name: "error in TakeNewSnapshot",
			mocks: func(diffGenMock *MockdiffGenerator, metaGenMock *MockmetadataGenerator, snapGenMock *MocksnapshotGenerator) {
				snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).Times(1).Return(testErr1)
			},
			data:        nil,
			newSnapshot: true,
			expectedErr: testErr1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()
			g, gCtx := errgroup.WithContext(ctx)

			snapshotGenMock := NewMocksnapshotGenerator(ctrl)
			diffGenMock := NewMockdiffGenerator(ctrl)
			metadataGenMock := NewMockmetadataGenerator(ctrl)
			tt.mocks(diffGenMock, metadataGenMock, snapshotGenMock)

			stray, err := GetStray(ctx, nil, ModeDisabled, snapshotGenMock, metadataGenMock, diffGenMock)
			assert.NoError(t, err)

			stray.NewDiffAndMetadata(g, gCtx, tt.data, tt.add, tt.newSnapshot)
			err = waitOnGroupErrors(g)
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestCheckCounter(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	snapshotGenMock := NewMocksnapshotGenerator(ctrl)

	tests := []struct {
		name                string
		intervalLimit       int
		expectedCount       int
		expectedNewSnapshot bool
	}{
		{
			name:                "test count increment",
			intervalLimit:       2,
			expectedCount:       1,
			expectedNewSnapshot: false,
		},
		{
			name:                "test count increment and reset",
			intervalLimit:       2,
			expectedCount:       0,
			expectedNewSnapshot: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			strayConfig := &StrayConfig{snapshotIntervalLimit: tt.intervalLimit}
			stray, err := GetStray(ctx, strayConfig, ModeDisabled, snapshotGenMock, nil, nil)
			assert.NoError(t, err)

			newSnapshot := stray.CheckCounter(ctx)

			assert.Equal(t, tt.expectedCount, stray.counter)
			assert.Equal(t, tt.expectedNewSnapshot, newSnapshot)
		})
	}
}

func TestUpdateStateEarlyReturn(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	snapGenMock := NewMocksnapshotGenerator(ctrl)
	diffGenMock := NewMockdiffGenerator(ctrl)

	// configure replica mode
	enableStray := false
	enableSLSDataSync := true

	// no need to add metadataGenerator mock because its not called in this test
	stray, err := GetStray(t.Context(), nil, GetMode(enableStray, enableSLSDataSync), snapGenMock, nil, diffGenMock)
	assert.NoError(t, err)
	assert.Equal(t, ModeReplica, stray.mode)

	// passing quarantine as input to trigger AddDiffQuarantines
	input := []*model.Quarantine{{}}

	// making sure the following methods are not called because of early return due to replica mode
	diffGenMock.EXPECT().AddDiffQuarantines(gomock.Any()).Times(0)
	snapGenMock.EXPECT().TakeNewSnapshot(gomock.Any()).Times(0)

	err = stray.updateState(t.Context(), input, false)
	assert.NoError(t, err)
}
