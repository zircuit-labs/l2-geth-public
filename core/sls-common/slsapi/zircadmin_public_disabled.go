package slsapi

type (
	ZircAdminAPIPublicDisabled struct{}
)

func NewZircAdminAPIPublicDisabled() *ZircAdminAPIPublicDisabled {
	return &ZircAdminAPIPublicDisabled{}
}

func (z *ZircAdminAPIPublicDisabled) GetFormattedPayload(method string, args []any) string {
	return ""
}
