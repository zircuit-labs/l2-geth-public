package slsapi

import (
	"context"
	"errors"
	"time"

	"github.com/zircuit-labs/zkr-go-common/stores/pg"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/sls-common/slslog"
	commonStorage "github.com/zircuit-labs/l2-geth/core/sls-common/storage"
	"github.com/zircuit-labs/l2-geth/log"
)

//go:generate go tool mockgen -source zirc.go -destination mock_zirc.go -package slsapi

type (
	SlsAPI struct {
		store  QuarantineStorage
		logger log.Logger
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

	QuarantineStorage interface {
		IsQuarantined(ctx context.Context, txHash common.Hash) (bool, error)
		Quarantined(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error)
		All(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error)
		Release(ctx context.Context, txHash common.Hash, reason string) (bool, error)
		SetExpiresOn(ctx context.Context, txHash common.Hash, expiresOn time.Time, releaser common.Address) (bool, error)
		FindByHash(ctx context.Context, txHash common.Hash) (*model.Quarantine, error)
		GetAdminAddresses(ctx context.Context) ([]common.Address, error)
		AdminAddresses(ctx context.Context, opts pg.QueryOpts) ([]*model.Admin, error)
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

func NewZircAPI(store QuarantineStorage) *SlsAPI {
	return &SlsAPI{
		store:  store,
		logger: slslog.NewWith("rpc_handler", "zirc_api"),
	}
}

type defaultQueryOpts struct{}

func (d defaultQueryOpts) GetLimit() int {
	return 0
}

func (d defaultQueryOpts) GetCursor() pg.Cursor {
	return pg.Cursor{}
}

var DefaultQueryOpts = defaultQueryOpts{}
var (
	ErrSlsStray               = errors.New("error processing data")
	ErrStorage                = errors.New("error retrieving data")
	ErrAlreadyInTrustList     = errors.New("one or more addresses are already trusted")
	ErrAlreadyInIntegrityList = errors.New("one or more addresses are already in the integrity list")
)

func (z *SlsAPI) GetQuarantined(ctx context.Context, from *common.Address) ([]*Quarantine, error) {
	_, items, err := z.store.Quarantined(ctx, defaultQueryOpts{}, from)
	if err != nil {
		z.logger.With("err", err).Warn("Quarantined returned an error")
		return nil, ErrStorage
	}

	return NewQuarantineList(items)
}

var ErrRetrievingQuarantine = errors.New("error retrieving quarantine")

type (
	IsQuarantinedResponse struct {
		IsQuarantined bool
		Quarantine    *Quarantine
		TxData        []byte
	}
)

func (z *SlsAPI) IsQuarantined(ctx context.Context, txHash common.Hash) (*IsQuarantinedResponse, error) {
	quarantine, err := z.store.FindByHash(ctx, txHash)
	if errors.Is(err, commonStorage.ErrTransactionNotFound) {
		return &IsQuarantinedResponse{
			IsQuarantined: false,
			Quarantine:    nil,
			TxData:        nil,
		}, nil
	}
	if err != nil {
		z.logger.With("err", err).Warn("FindByHash returned an error")
		return nil, ErrStorage
	}
	q, err := NewQuarantine(quarantine)
	if err != nil {
		z.logger.With("err", err).Warn("Can't convert model to quarantine")
		return nil, ErrRetrievingQuarantine
	}

	return &IsQuarantinedResponse{
		IsQuarantined: !quarantine.IsReleased,
		Quarantine:    q,
		TxData:        quarantine.TxData,
	}, nil
}

func (z *SlsAPI) GetQuarantineHistory(ctx context.Context, offset, limit int, from *common.Address) ([]*Quarantine, error) {
	_, items, err := z.store.All(ctx, defaultQueryOpts{}, from)
	if err != nil {
		z.logger.With("err", err).Warn("All returned an error")
		return nil, ErrStorage
	}

	return NewQuarantineList(items)
}

func (z *SlsAPI) GetAdminAddresses(ctx context.Context) ([]common.Address, error) {
	addrs, err := z.store.GetAdminAddresses(ctx)
	if err != nil {
		z.logger.With("err", err).Warn("GetAdminAddresses returned an error")
		return nil, ErrStorage
	}

	return addrs, nil
}
