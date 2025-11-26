package sls

import (
	"errors"
	"testing"
)

func TestDetectorTypeFromString(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		wantDetectorType DetectorType
		wantErr          error
	}{
		{
			name:             "Forkchoice string",
			input:            DetectorTypeStringForkChoice,
			wantDetectorType: DetectorTypeForkChoice,
			wantErr:          nil,
		},
		{
			name:             "Legacypool string",
			input:            DetectorTypeStringLegacyPool,
			wantDetectorType: DetectorTypeLegacyPool,
			wantErr:          nil,
		},
		{
			name:             "Block string",
			input:            DetectorTypeStringBlock,
			wantDetectorType: DetectorTypeBlock,
			wantErr:          nil,
		},
		{
			name:             "Unknown string",
			input:            "unknown",
			wantDetectorType: DetectorType(0),
			wantErr:          ErrUnknownDetectorTypeString,
		},
		{
			name:             "Empty string",
			input:            "",
			wantDetectorType: DetectorType(0),
			wantErr:          ErrUnknownDetectorTypeString,
		},
		{
			name:             "Case mismatch - uppercase",
			input:            "FORKCHOICE",
			wantDetectorType: DetectorType(0),
			wantErr:          ErrUnknownDetectorTypeString,
		},
		{
			name:             "Invalid string with spaces",
			input:            "fork choice",
			wantDetectorType: DetectorType(0),
			wantErr:          ErrUnknownDetectorTypeString,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDetectorType, gotErr := DetectorTypeFromString(tt.input)

			if gotDetectorType != tt.wantDetectorType {
				t.Errorf("DetectorTypeFromString() gotDetectorType = %v, want %v", gotDetectorType, tt.wantDetectorType)
			}

			if tt.wantErr != nil {
				if gotErr == nil {
					t.Errorf("DetectorTypeFromString() gotErr = nil, want error")
				} else if !errors.Is(gotErr, tt.wantErr) {
					t.Errorf("DetectorTypeFromString() gotErr = %v, want %v", gotErr, tt.wantErr)
				}
			} else if gotErr != nil {
				t.Errorf("DetectorTypeFromString() gotErr = %v, want nil", gotErr)
			}
		})
	}
}

func TestDetectorTypeRoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		detectorType DetectorType
	}{
		{
			name:         "Forkchoice round trip",
			detectorType: DetectorTypeForkChoice,
		},
		{
			name:         "Legacypool round trip",
			detectorType: DetectorTypeLegacyPool,
		},
		{
			name:         "Block round trip",
			detectorType: DetectorTypeBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDetectorType, err := DetectorTypeFromString(tt.detectorType.String())
			if err != nil {
				t.Fatalf("DetectorTypeFromString() error = %v", err)
			}

			if gotDetectorType != tt.detectorType {
				t.Errorf("Round trip failed: started with %v, got %v", tt.detectorType, gotDetectorType)
			}
		})
	}
}

func TestDetectorTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "ForkChoice constant value",
			constant: DetectorTypeStringForkChoice,
			expected: "forkchoice",
		},
		{
			name:     "LegacyPool constant value",
			constant: DetectorTypeStringLegacyPool,
			expected: "legacypool",
		},
		{
			name:     "Block constant value",
			constant: DetectorTypeStringBlock,
			expected: "block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Constant value = %v, want %v", tt.constant, tt.expected)
			}
		})
	}
}

func TestDetectorTypeEnumValues(t *testing.T) {
	tests := []struct {
		name         string
		detectorType DetectorType
		expected     int
	}{
		{
			name:         "Forkchoice enum value",
			detectorType: DetectorTypeForkChoice,
			expected:     0,
		},
		{
			name:         "Legacypool enum value",
			detectorType: DetectorTypeLegacyPool,
			expected:     1,
		},
		{
			name:         "Block enum value",
			detectorType: DetectorTypeBlock,
			expected:     2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.detectorType) != tt.expected {
				t.Errorf("Enum value = %v, want %v", int(tt.detectorType), tt.expected)
			}
		})
	}
}

func TestDetectorType_String(t *testing.T) {
	tests := []struct {
		name         string
		detectorType DetectorType
		want         string
	}{
		{
			name:         "Forkchoice detector type",
			detectorType: DetectorTypeForkChoice,
			want:         DetectorTypeStringForkChoice,
		},
		{
			name:         "Legacypool detector type",
			detectorType: DetectorTypeLegacyPool,
			want:         DetectorTypeStringLegacyPool,
		},
		{
			name:         "Block detector type",
			detectorType: DetectorTypeBlock,
			want:         DetectorTypeStringBlock,
		},
		{
			name:         "Unknown detector type",
			detectorType: DetectorType(999),
			want:         "unknown",
		},
		{
			name:         "Invalid negative detector type",
			detectorType: DetectorType(-1),
			want:         "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.detectorType.String()
			if got != tt.want {
				t.Errorf("DetectorType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
