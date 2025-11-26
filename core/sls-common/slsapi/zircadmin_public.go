package slsapi

import (
	"time"
)

//go:generate go tool mockgen -source zircadmin_public.go -destination mock_zircadmin_public.go -package slsapi

type (
	ZircAdminAPIPublic struct {
		storage          QuarantineStorage
		payloadFormatter PayloadFormatter
	}

	PayloadFormatter interface {
		Format(currTime time.Time, method string, args []any) string
	}
)

func NewZircAdminAPIPublic(storage QuarantineStorage, payloadFormatter PayloadFormatter) *ZircAdminAPIPublic {
	return &ZircAdminAPIPublic{storage: storage, payloadFormatter: payloadFormatter}
}

func (z *ZircAdminAPIPublic) GetFormattedPayload(method string, args []any) string {
	return z.payloadFormatter.Format(time.Now().UTC(), method, args)
}
