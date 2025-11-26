package slsstray

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/sls-common/slsapi"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/zkr-go-common/stores/pg"
	"go.uber.org/mock/gomock"
)

func setupQuarantineAdmin() ([]*model.Quarantine, []*model.Admin) {
	addr1 := "0x0000000000000000000000000000000000000000"
	addr2 := "0xaaaa000000000000000000000000000000000000"
	admn1 := &model.Admin{Address: addr1}
	admn2 := &model.Admin{Address: addr2}

	tx := types.NewTx(&types.LegacyTx{})
	detector := "test detector"
	reason := "test reason"
	tn := time.Now()
	q1 := &model.Quarantine{
		ExpiresOn:         &tn,
		TxData:            tx.Data(),
		TxHash:            tx.Hash().String(),
		Data:              tx.Data(),
		QuarantinedAt:     tn,
		QuarantinedReason: reason,
		QuarantinedBy:     detector,
		ReleasedAt:        tn,
		ReleasedReason:    reason,
		ReleasedBy:        addr1,
		IsReleased:        false,
		From:              addr1,
		To:                addr1,
		Nonce:             0,
		Loss:              uint256.NewInt(1),
		Value:             uint256.NewInt(1),
		QuarantineType:    model.PoolQuarantineType,
	}
	return []*model.Quarantine{q1}, []*model.Admin{admn1, admn2}
}

func setupStore(t *testing.T) *MockslsStore {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	return NewMockslsStore(ctrl)
}

func setupSnapshot(t *testing.T, basePath string) {
	store := setupStore(t)
	snapGen, err := NewSnapshotGenerator(store)
	assert.NoError(t, err)
	snapGen.SetConfig(&SnapshotConfig{storagePath: basePath})

	qs, ads := setupQuarantineAdmin()
	snapshot := &Snapshot{Timestamp: time.Now(), Quarantine: qs, Admin: ads}
	_, err = snapGen.StoreSnapshot(snapshot)
	assert.NoError(t, err)

	time.Sleep(1 * time.Second)
	snapshot = &Snapshot{Timestamp: time.Now(), Quarantine: qs}
	_, err = snapGen.StoreSnapshot(snapshot)
	assert.NoError(t, err)
}

func TestGetSnapshot(t *testing.T) {
	store := setupStore(t)

	qs, ads := setupQuarantineAdmin()
	store.EXPECT().AdminAddresses(t.Context(), gomock.Any()).Times(1).Return(ads, nil)
	store.EXPECT().Quarantined(t.Context(), gomock.Any(), gomock.Any()).Times(1).Return(pg.Cursor{}, qs, nil)

	snapGen, err := NewSnapshotGenerator(store)
	assert.NoError(t, err)
	snapshot, err := snapGen.GetSnapshot(t.Context())
	assert.Equal(t, nil, err)
	assert.Equal(t, qs[0], snapshot.Quarantine[0])
	assert.Equal(t, ads[0].Address, snapshot.Admin[0].Address)
	assert.Equal(t, ads[1].Address, snapshot.Admin[1].Address)
}

func TestGetSnapshotErrors(t *testing.T) {
	store := setupStore(t)
	store.EXPECT().AdminAddresses(gomock.Any(), slsapi.DefaultQueryOpts).Times(1).Return([]*model.Admin{}, errors.New("error 1"))
	store.EXPECT().AdminAddresses(gomock.Any(), slsapi.DefaultQueryOpts).Times(1).Return([]*model.Admin{}, nil)
	store.EXPECT().Quarantined(gomock.Any(), slsapi.DefaultQueryOpts, nil).Times(1).Return(pg.Cursor{}, []*model.Quarantine{}, errors.New("error 2"))

	snapGen, err := NewSnapshotGenerator(store)
	assert.NoError(t, err)
	_, err = snapGen.GetSnapshot(t.Context())
	assert.ErrorContains(t, err, "error 1")
	_, err = snapGen.GetSnapshot(t.Context())
	assert.ErrorContains(t, err, "error 2")
}

func TestGetLatestSnapshot(t *testing.T) {
	basePath := filepath.Join(os.TempDir(), "tmp/sls/snapshot")
	setupSnapshot(t, basePath)
	store := setupStore(t)

	snapGen, err := NewSnapshotGenerator(store)
	assert.NoError(t, err)
	snapGen.SetConfig(&SnapshotConfig{storagePath: basePath})

	snapshot, _, err := getLatestSnapshot(snapGen.gzipper, basePath)
	assert.NoError(t, err)

	// latest snapshot should not contain admin data
	if len(snapshot.Admin) != 0 {
		t.Errorf("len(snapshot.Admin) expected to be 0, got: %d", len(snapshot.Admin))
	}
	os.RemoveAll(basePath)
}

func TestGetLatestSnapshotError(t *testing.T) {
	basePath := filepath.Join(os.TempDir(), "tmp/sls/snapshot")
	os.RemoveAll(basePath)
	store := setupStore(t)

	snapGen, err := NewSnapshotGenerator(store)
	assert.NoError(t, err)
	snapGen.SetConfig(&SnapshotConfig{storagePath: basePath})

	os.Mkdir(basePath, 0755)
	_, _, err = getLatestSnapshot(snapGen.gzipper, basePath)
	assert.ErrorIs(t, err, ErrNoSnapshotFound)
	os.RemoveAll(basePath)
}
