package ethapi

import (
	"context"
	"errors"
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	"github.com/zircuit-labs/l2-geth-public/core/sls/slslog"
	storage2 "github.com/zircuit-labs/l2-geth-public/core/sls/storage"
	"github.com/zircuit-labs/l2-geth-public/log"
)

//go:generate mockgen -source zirc.go -destination mock_zirc.go -package ethapi

type (
	ZircAPI struct {
		storage storage
		logger  log.Logger
	}

	Quarantine struct {
		TransactionHash   string
		QuarantinedAt     time.Time
		ExpiresOn         *time.Time
		ReleasedReason    string
		QuarantinedBy     string
		QuarantinedReason string
		ReleasedBy        string
	}

	storage interface {
		IsQuarantined(ctx context.Context, txHash common.Hash) (bool, error)
		Quarantined(ctx context.Context, from *common.Address) ([]*model.Quarantine, int, error)
		All(ctx context.Context, offset, limit int, from *common.Address) ([]*model.Quarantine, int, error)
		Release(ctx context.Context, txHash common.Hash, reason string) (bool, error)
		SetExpiresOn(ctx context.Context, txHash common.Hash, expiresOn time.Time, releaser common.Address) (bool, error)
		FindByHash(ctx context.Context, txHash common.Hash) (*model.Quarantine, error)
		AddIntegrityListAddresses(ctx context.Context, addresses []common.Address) error
		RemoveIntegrityListAddresses(ctx context.Context, addresses []common.Address) error
		AddressesInIntegrityList(ctx context.Context, addresses []common.Address) ([]common.Address, error)
		GetIntegrityListAddresses(ctx context.Context) ([]common.Address, error)
		AddressesInTrustList(ctx context.Context, addresses []common.Address) ([]common.Address, error)
		AddTrustListAddresses(ctx context.Context, addresses []common.Address) error
		RemoveTrustListAddresses(ctx context.Context, addresses []common.Address) error
		GetTrustListAddresses(ctx context.Context) ([]common.Address, error)
		GetAdminAddresses(ctx context.Context) ([]common.Address, error)
		IsQuarantinedAndScanned(ctx context.Context, txHash common.Hash) (*model.TransactionResult, error)
		IsAdmin(ctx context.Context, address common.Address) (bool, error)
	}
)

func NewQuarantineList(list []*model.Quarantine) ([]*Quarantine, error) {
	l := make([]*Quarantine, 0, len(list))
	for _, quarantine := range list {
		q, err := NewQuarantine(quarantine)
		if err != nil {
			return nil, err
		}

		l = append(l, q)
	}

	return l, nil
}

func NewQuarantine(q *model.Quarantine) (*Quarantine, error) {
	tx, err := q.Tx()
	if err != nil {
		return nil, err
	}

	return &Quarantine{
		TransactionHash:   tx.Hash().String(),
		ExpiresOn:         q.ExpiresOn,
		QuarantinedBy:     q.QuarantinedBy,
		QuarantinedAt:     q.QuarantinedAt,
		QuarantinedReason: q.QuarantinedReason,
		ReleasedBy:        q.ReleasedBy,
		ReleasedReason:    q.ReleasedReason,
	}, nil
}

func NewZircAPI(storage storage) *ZircAPI {
	return &ZircAPI{
		storage: storage,
		logger:  slslog.NewWith("rpc_handler", "zirc_api"),
	}
}

var (
	ErrStorage                = errors.New("error retrieving data")
	ErrAlreadyInTrustList     = errors.New("one or more addresses are already trusted")
	ErrAlreadyInIntegrityList = errors.New("one or more addresses are already in the integrity list")
)

func (z *ZircAPI) GetQuarantined(ctx context.Context, from *common.Address) ([]*Quarantine, error) {
	items, _, err := z.storage.Quarantined(ctx, from)
	if err != nil {
		z.logger.With("err", err).Warn("Quarantined returned an error")
		return nil, ErrStorage
	}

	return NewQuarantineList(items)
}

var (
	ErrRetrievingQuarantine = errors.New("error retrieving quarantine")
)

type (
	IsQuarantinedResponse struct {
		WasScanned    bool
		IsQuarantined bool
		Quarantine    *Quarantine
	}
)

func (z *ZircAPI) IsQuarantined(ctx context.Context, txHash common.Hash) (*IsQuarantinedResponse, error) {
	result, err := z.storage.IsQuarantinedAndScanned(ctx, txHash)
	if errors.Is(err, storage2.ErrTransactionNotFound) {
		return &IsQuarantinedResponse{
			IsQuarantined: false,
			Quarantine:    nil,
			WasScanned:    false,
		}, nil // transaction was never scanned
	}
	if err != nil {
		z.logger.With("err", err).Warn("IsQuarantinedAndScanned returned an error")
		return nil, ErrStorage
	}

	if result.Quarantined && result.Quarantine != nil {
		q, err := NewQuarantine(result.Quarantine)
		if err != nil {
			z.logger.With("err", err).Warn("Can't convert model to quarantine")
			return nil, ErrRetrievingQuarantine
		}
		return &IsQuarantinedResponse{
			IsQuarantined: !result.Quarantine.IsReleased,
			Quarantine:    q,
			WasScanned:    true,
		}, nil
	}

	// Transaction was scanned and not quarantined
	return &IsQuarantinedResponse{
		IsQuarantined: false,
		Quarantine:    nil,
		WasScanned:    true,
	}, nil
}

func (z *ZircAPI) GetQuarantineHistory(ctx context.Context, offset, limit int, from *common.Address) ([]*Quarantine, error) {
	items, _, err := z.storage.All(ctx, offset, limit, from)
	if err != nil {
		z.logger.With("err", err).Warn("All returned an error")
		return nil, ErrStorage
	}

	return NewQuarantineList(items)
}

func (z *ZircAPI) GetAdminAddresses(ctx context.Context) ([]common.Address, error) {
	addrs, err := z.storage.GetAdminAddresses(ctx)
	if err != nil {
		z.logger.With("err", err).Warn("GetAdminAddresses returned an error")
		return nil, ErrStorage
	}

	return addrs, nil
}
