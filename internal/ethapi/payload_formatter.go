package ethapi

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zircuit-labs/l2-geth/common"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/slslog"
	"github.com/zircuit-labs/l2-geth/log"
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
		if len(v) > 0 {
			// If the first element is a map[string]interface{}, treat as slice of JSON‐objects
			if _, ok := v[0].(map[string]any); ok {
				rows := make([]string, len(v))
				for i, rawElem := range v {
					m := rawElem.(map[string]any)
					rows[i] = p.formatMap(m)
				}
				return fmt.Sprintf("[%s]", strings.Join(rows, sep))
			}
		}
		// Otherwise, generic []any—recurse on each element
		strs := make([]string, len(v))
		for i, val := range v {
			strs[i] = p.formatArg(val)
		}
		return fmt.Sprintf("[%s]", strings.Join(strs, sep))
	case map[string]any:
		return fmt.Sprintf("[%s]", p.formatMap(v))
	case []common.Address:
		strs := make([]string, len(v))
		for i, val := range v {
			strs[i] = p.formatArg(val)
		}
		return fmt.Sprintf("[%s]", strings.Join(strs, sep))
	case []slsCommon.ListItem:
		// Build [ [addr,ref], [addr,ref], … ]
		strs := make([]string, len(v))
		for i, item := range v {
			strs[i] = fmt.Sprintf("[%s,%s]", item.Address.String(), item.Reference)
		}
		return fmt.Sprintf("[%s]", strings.Join(strs, sep))
	case common.Address:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (p *PayloadFormatter) formatMap(m map[string]any) string {
	// extract and sort keys alphabetically
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// format each value in key order
	vals := make([]string, len(keys))
	for i, key := range keys {
		vals[i] = p.formatArg(m[key])
	}
	return fmt.Sprintf("[%s]", strings.Join(vals, sep))
}
