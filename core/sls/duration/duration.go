package duration

import (
	"time"
)

type (
	// Duration implements the unmarshal interface.
	// The default TOML decoding package used by geth doesn't natively understand supports.
	// Following is an adaptation of their guideline for integrating time.Duration compatibility.
	// Reference: https://github.com/naoina/toml?tab=readme-ov-file#using-the-encodingtextunmarshaler-interface
	Duration time.Duration
)

// UnmarshalText implements encoding.TextUnmarshaler
func (d *Duration) UnmarshalText(data []byte) error {
	duration, err := time.ParseDuration(string(data))
	if err != nil {
		return err
	}

	*d = Duration(duration)
	return nil
}

// MarshalText implements encoding.TextMarshaler
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}
