package model

import (
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

var (
	tx       = types.NewTx(&types.DepositTx{})
	from     = common.Address{}
	detector = "Test Detector"
	reason   = "Test Reason"
)

func TestNewQuarantineNormal(t *testing.T) {
	t.Parallel()

	duration := time.Second

	quarantine, err := NewQuarantine(tx, detector, reason, from.String(), duration, 0, PoolQuarantineType)
	assert.NoError(t, err)

	assert.Equal(t, detector, quarantine.QuarantinedBy)
	assert.Equal(t, reason, quarantine.QuarantinedReason)
	assert.Equal(t, tx.Hash().String(), quarantine.TxHash)
	assert.NotNil(t, quarantine.ExpiresOn)
	assert.Equal(t, uint256.MustFromBig(tx.Value()), quarantine.Value)
	assert.Equal(t, tx.Nonce(), quarantine.Nonce)
	assert.Equal(t, from.String(), quarantine.From)
	assert.Equal(t, PoolQuarantineType, quarantine.QuarantineType)
	assert.False(t, quarantine.IsReleased)
}

func TestNewQuarantineNoExpiryDate(t *testing.T) {
	t.Parallel()

	duration := time.Duration(0)

	quarantine, err := NewQuarantine(tx, detector, reason, from.String(), duration, 0, PoolQuarantineType)
	assert.NoError(t, err)

	assert.Equal(t, detector, quarantine.QuarantinedBy)
	assert.Equal(t, reason, quarantine.QuarantinedReason)
	assert.Equal(t, tx.Hash().String(), quarantine.TxHash)
	assert.Nil(t, quarantine.ExpiresOn)
	assert.Equal(t, uint256.MustFromBig(tx.Value()), quarantine.Value)
	assert.Equal(t, tx.Nonce(), quarantine.Nonce)
	assert.Equal(t, from.String(), quarantine.From)
	assert.Equal(t, PoolQuarantineType, quarantine.QuarantineType)
	assert.False(t, quarantine.IsReleased)
}

func TestNewQuarantineRejected(t *testing.T) {
	t.Parallel()

	loss := uint64(100)

	quarantine, err := NewQuarantineRejected(tx, detector, reason, from.String(), loss)
	assert.NoError(t, err)

	assert.Equal(t, detector, quarantine.QuarantinedBy)
	assert.Equal(t, reason, quarantine.QuarantinedReason)
	assert.Equal(t, tx.Hash().String(), quarantine.TxHash)
	assert.Equal(t, uint256.MustFromBig(tx.Value()), quarantine.Value)
	assert.Equal(t, tx.Nonce(), quarantine.Nonce)
	assert.Equal(t, from.String(), quarantine.From)
	assert.Equal(t, APIRejectedQuarantineType, quarantine.QuarantineType)
	assert.False(t, quarantine.IsReleased)
	assert.Equal(t, uint256.NewInt(loss), quarantine.Loss)
}

func TestShouldBeReleased(t *testing.T) {
	t.Parallel()

	duration := time.Second
	quarantine, err := NewQuarantine(tx, detector, reason, from.String(), duration, 0, PoolQuarantineType)
	assert.NoError(t, err)

	// Test before expiration
	assert.False(t, quarantine.ShouldBeReleased())

	// Wait for the quarantine to expire
	time.Sleep(2 * time.Second)
	assert.True(t, quarantine.ShouldBeReleased())
}

func TestTx(t *testing.T) {
	t.Parallel()

	quarantine, err := NewQuarantine(tx, detector, reason, from.String(), time.Second, 0, PoolQuarantineType)
	assert.NoError(t, err)

	restoredTx, err := quarantine.Tx()
	assert.NoError(t, err)
	assert.Equal(t, tx.Hash(), restoredTx.Hash())
}

func TestSetExpiresOn(t *testing.T) {
	t.Parallel()

	quarantine, err := NewQuarantine(tx, detector, reason, from.String(), time.Second, 0, PoolQuarantineType)
	assert.NoError(t, err)

	newExpiresOn := time.Now().Add(10 * time.Second)
	quarantine.SetExpiresOn(newExpiresOn)

	assert.Equal(t, newExpiresOn, *quarantine.ExpiresOn)
}

func TestSetReleaser(t *testing.T) {
	t.Parallel()

	quarantine, err := NewQuarantine(tx, detector, reason, from.String(), time.Second, 0, PoolQuarantineType)
	assert.NoError(t, err)

	releaser := common.HexToAddress("0x0")
	quarantine.SetReleaser(releaser)

	assert.Equal(t, releaser.String(), quarantine.ReleasedBy)
}

func TestRelease(t *testing.T) {
	t.Parallel()

	quarantine, err := NewQuarantine(tx, detector, reason, from.String(), time.Second, 0, PoolQuarantineType)
	assert.NoError(t, err)

	releaseReason := "Test Reason"
	quarantine.Release(releaseReason)

	assert.True(t, quarantine.IsReleased)
	assert.Equal(t, releaseReason, quarantine.ReleasedReason)
	assert.WithinDuration(t, time.Now(), quarantine.ReleasedAt, time.Second)
}
