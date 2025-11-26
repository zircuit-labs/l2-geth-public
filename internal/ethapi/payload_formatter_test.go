package ethapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/common"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
)

func TestPayloadHasher(t *testing.T) {
	t.Parallel()

	currTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	tests := []struct {
		name        string
		method      string
		args        []any
		currentTime time.Time
		expected    string
	}{
		{
			name:        "1 string argument",
			currentTime: currTime,
			method:      "admin_addToList",
			args:        []any{"0xdead"},
			expected:    "1609459200,admin_addtolist,0xdead",
		},
		{
			name:        "No arguments",
			currentTime: currTime,
			method:      "admin_noArgs",
			args:        []any{},
			expected:    "1609459200,admin_noargs",
		},
		{
			name:        "Multiple string arguments",
			currentTime: currTime,
			method:      "admin_addToList",
			args:        []any{"0xdead", "0xbeef"},
			expected:    "1609459200,admin_addtolist,0xdead,0xbeef",
		},
		{
			name:        "Slice of strings",
			currentTime: currTime,
			method:      "admin_addToList",
			args:        []any{[]any{"0xdead", "0xbeef"}},
			expected:    "1609459200,admin_addtolist,[0xdead,0xbeef]",
		},
		{
			name:        "Slice of common.Address",
			currentTime: currTime,
			method:      "admin_addAddresses",
			args:        []any{[]common.Address{addr1, addr2}},
			expected:    "1609459200,admin_addaddresses,[0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222]",
		},
		{
			name:        "Single common.Address",
			currentTime: currTime,
			method:      "admin_addAddress",
			args:        []any{addr1},
			expected:    "1609459200,admin_addaddress,0x1111111111111111111111111111111111111111",
		},
		{
			name:        "Unrecognized type argument",
			currentTime: currTime,
			method:      "admin_unrecognizedType",
			args:        []any{struct{}{}},
			expected:    "1609459200,admin_unrecognizedtype,{}",
		},
		{
			name:        "Time not aligned to start of minute",
			currentTime: currTime.Add(time.Second * 18),
			method:      "admin_timeCheck",
			args:        []any{"0xdead"},
			expected:    "1609459200,admin_timecheck,0xdead",
		},
		{
			name:        "Single JSON-object (map[string]interface{})",
			currentTime: currTime,
			method:      "admin_addToList",
			args: []any{
				map[string]any{
					"address":   addr1,
					"reference": "foo",
				},
			},
			expected: "1609459200,admin_addtolist,[[0x1111111111111111111111111111111111111111,foo]]",
		},
		{
			name:        "Slice of JSON-objects (map[string]interface{})",
			currentTime: currTime,
			method:      "admin_addToList",
			args: []any{
				[]any{
					map[string]any{
						"address":   addr1,
						"reference": "foo",
					},
					map[string]any{
						"address":   addr2,
						"reference": "boo",
					},
				},
			},
			expected: "1609459200,admin_addtolist,[[0x1111111111111111111111111111111111111111,foo],[0x2222222222222222222222222222222222222222,boo]]",
		},
		{
			name:        "Single slsCommon.ListItem",
			currentTime: currTime,
			method:      "admin_addToList",
			args: []any{[]slsCommon.ListItem{
				{Address: addr1, Reference: "foo"},
			}},
			expected: "1609459200,admin_addtolist,[[0x1111111111111111111111111111111111111111,foo]]",
		},
		{
			name:        "Slice of slsCommon.ListItem",
			currentTime: currTime,
			method:      "admin_addToList",
			args: []any{[]slsCommon.ListItem{
				{Address: addr1, Reference: "foo"},
				{Address: addr2, Reference: "boo"},
			}},
			expected: "1609459200,admin_addtolist,[[0x1111111111111111111111111111111111111111,foo],[0x2222222222222222222222222222222222222222,boo]]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := NewPayloadFormatter()
			payload := p.Format(tt.currentTime, tt.method, tt.args)
			assert.Equal(t, tt.expected, payload)
		})
	}
}
