package ethapi

import (
	"context"
	"errors"
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/slslog"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/rpc"
)

var (
	ErrCantRetrieveSigner = errors.New("can't retrieve signer")
)

type (
	ZircAdminAPI struct {
		storage storage
		logger  log.Logger
	}
)

func NewZircAdminAPI(storage storage) *ZircAdminAPI {
	return &ZircAdminAPI{
		storage: storage,
		logger:  slslog.NewWith("rpc_handler", "zirc_admin_api"),
	}
}

func (z *ZircAdminAPI) ReleaseTransactionQuarantine(ctx context.Context, hash common.Hash) (bool, error) {
	signer, ok := rpc.SignerFromContext(ctx)
	if !ok {
		z.logger.With("signer", signer).Warn("Can't retrieve signer from context")
		return false, ErrCantRetrieveSigner
	}

	success, err := z.storage.SetExpiresOn(ctx, hash, time.Now(), signer)
	if err != nil {
		z.logger.With("error", err, "hash", hash.Hex()).Warn("Failed to release transaction quarantine")
		return false, ErrStorage
	}

	return success, nil
}

func (z *ZircAdminAPI) ExtendTransactionQuarantine(ctx context.Context, hash common.Hash, minutes int) (bool, error) {
	signer, ok := rpc.SignerFromContext(ctx)
	if !ok {
		z.logger.With("signer", signer).Warn("Can't retrieve signer from context")
		return false, ErrCantRetrieveSigner
	}

	success, err := z.storage.SetExpiresOn(ctx, hash, time.Now().Add(time.Minute*time.Duration(minutes)), signer)
	if err != nil {
		z.logger.With("error", err, "hash", hash.Hex(), "minutes", minutes).Warn("Failed to extend transaction quarantine")
		return false, ErrStorage
	}

	return success, nil
}

func (z *ZircAdminAPI) GetIntegrityListAddresses(ctx context.Context) ([]common.Address, error) {
	addresses, err := z.storage.GetIntegrityListAddresses(ctx)
	if err != nil {
		z.logger.With("error", err).Warn("Failed to get integrity list addresses")
		return nil, ErrStorage
	}

	return addresses, nil
}

func (z *ZircAdminAPI) AddAddressesToIntegrityList(ctx context.Context, address []common.Address) (bool, error) {
	// Check if any of the addresses are already trusted
	alreadyTrusted, err := z.storage.AddressesInTrustList(ctx, address)
	if err != nil {
		z.logger.With("error", err).Warn("Failed to check if addresses are in trust list")
		return false, ErrStorage
	}
	if len(alreadyTrusted) > 0 {
		return false, ErrAlreadyInTrustList
	}

	err = z.storage.AddIntegrityListAddresses(ctx, address)
	if err != nil {
		z.logger.With("error", err, "addresses", address).Warn("Failed to add addresses to integrity list")
		return false, ErrStorage
	}

	return true, nil
}

func (z *ZircAdminAPI) RemoveAddressesFromIntegrityList(ctx context.Context, address []common.Address) (bool, error) {
	err := z.storage.RemoveIntegrityListAddresses(ctx, address)
	if err != nil {
		z.logger.With("error", err, "addresses", address).Warn("Failed to remove addresses from integrity list")
		return false, ErrStorage
	}

	return true, nil
}

func (z *ZircAdminAPI) GetTrustListAddresses(ctx context.Context) ([]common.Address, error) {
	addresses, err := z.storage.GetTrustListAddresses(ctx)
	if err != nil {
		z.logger.With("error", err).Warn("Failed to get trust list addresses")
		return nil, ErrStorage
	}

	return addresses, nil
}

func (z *ZircAdminAPI) AddAddressesToTrustList(ctx context.Context, address []common.Address) (bool, error) {
	// Check if any of the addresses are in the integrity list
	alreadyInIntegrityList, err := z.storage.AddressesInIntegrityList(ctx, address)
	if err != nil {
		z.logger.With("error", err).Warn("Failed to check if addresses are in integrity list")
		return false, ErrStorage
	}
	if len(alreadyInIntegrityList) > 0 {
		return false, ErrAlreadyInIntegrityList
	}

	err = z.storage.AddTrustListAddresses(ctx, address)
	if err != nil {
		z.logger.With("error", err, "addresses", address).Warn("Failed to add addresses to trust list")
		return false, ErrStorage
	}

	return true, nil
}

func (z *ZircAdminAPI) RemoveAddressesFromTrustList(ctx context.Context, address []common.Address) (bool, error) {
	err := z.storage.RemoveTrustListAddresses(ctx, address)
	if err != nil {
		z.logger.With("error", err, "addresses", address).Warn("Failed to remove addresses from trust list")
		return false, ErrStorage
	}

	return true, nil
}
