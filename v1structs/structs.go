package v1structs

type GetPublicKeyResponse struct {
	ArmoredPublicKey string `json:"armoredPublicKey"`
}

type SendSecretRequest struct {
	RecipientFingerprint   string `json:"recipientFingerprint"`
	ArmoredEncryptedSecret string `json:"armoredEncryptedSecret"`
}

type ErrorResponse struct {
	Detail string `json:"detail"`
}
