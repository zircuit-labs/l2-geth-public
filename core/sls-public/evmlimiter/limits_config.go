package evmlimiter

type LimitConfig struct {
}

func BuildLimitConfig() LimitConfig {
	return LimitConfig{}
}

const (
	WhalekillerLimitsDisabledEnv = ""
)

func WhalekillerLimitsEnabled() bool {
	return false
}
