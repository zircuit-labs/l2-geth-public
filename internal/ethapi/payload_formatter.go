package ethapi

import (
	"fmt"
	"strings"
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"

	"github.com/zircuit-labs/l2-geth-public/core/sls/slslog"
	"github.com/zircuit-labs/l2-geth-public/log"
)

type PayloadFormatter struct {
	logger log.Logger
}

const (
	sep = ","
)

// NewPayloadFormatter creates a new instance of PayloadFormatter.
func NewPayloadFormatter() *PayloadFormatter {
	return &PayloadFormatter{
		logger: slslog.NewWith("payload_formatter", true),
	}
}

// Format formats the provided method and arguments into a string, prefixed with the truncated minute epoch.
func (p *PayloadFormatter) Format(currTime time.Time, method string, args []any) string {
	minuteEpoch := currTime.Truncate(time.Minute).UTC().Unix()

	fullArgs := append([]any{minuteEpoch, method}, args...)
	formattedArgs := make([]string, len(fullArgs))

	for i, arg := range fullArgs {
		formattedArgs[i] = p.formatArg(arg)
	}

	formatted := strings.ToLower(strings.Join(formattedArgs, sep))

	// Logging the formatted payload with additional context.
	p.logger.With("method", method, "formatted", formatted).Info("Payload formatted")

	return formatted
}

// formatArg handles the formatting of individual arguments, including slices.
func (p *PayloadFormatter) formatArg(arg any) string {
	switch v := arg.(type) {
	case []any:
		strs := make([]string, len(v))
		for i, val := range v {
			strs[i] = p.formatArg(val)
		}
		return fmt.Sprintf("[%s]", strings.Join(strs, sep))
	case []common.Address:
		strs := make([]string, len(v))
		for i, val := range v {
			strs[i] = p.formatArg(val)
		}
		return fmt.Sprintf("[%s]", strings.Join(strs, sep))
	case common.Address:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}
