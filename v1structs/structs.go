package v1structs

type GetPublicKey struct {
	ArmoredPublicKey string `json:"armoredPublicKey"`
}

type ErrorResponse struct {
	Detail string `json:"detail"`
}
