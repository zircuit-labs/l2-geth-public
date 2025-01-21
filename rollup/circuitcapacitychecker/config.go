package circuitcapacitychecker

import "os"

type Config struct {
	Enabled       bool
	CheckDeposits bool
}

// checks flag that can be set during the runtime
func IsEnforcingMaxRowsRejection() bool {
	_, exists := os.LookupEnv("CCC_ENFORCE_MAX_ROWS_REJECTION")
	return exists
}
