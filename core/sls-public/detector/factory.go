package detector

import (
	"github.com/zircuit-labs/l2-geth/core/sls-common/detector"
	sls "github.com/zircuit-labs/l2-geth/core/sls-public"
)

type (
	Factory struct{}
)

func NewFactory(deps detector.Dependencies[sls.Config, sls.RefreshableGetter]) *Factory {
	return &Factory{}
}

func (f *Factory) Close() {}
