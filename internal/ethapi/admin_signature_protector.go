package ethapi

import (
	"context"
	"time"

	"github.com/zircuit-labs/l2-geth-public/accounts"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/slslog"
	"github.com/zircuit-labs/l2-geth-public/crypto"
	"github.com/zircuit-labs/l2-geth-public/log"
)

type (
	adminSignatureProtector struct {
		storage          storage
		logger           log.Logger
		payloadFormatter payloadFormatter
		signatureExpiry  time.Duration
	}
)

const (
	minSigExpiry = time.Minute
)

func newAdminSignatureProtector(storage storage, payloadFormatter payloadFormatter, signatureExpiry time.Duration) *adminSignatureProtector {
	// Ensure the signature expiry respects the minimum value
	if signatureExpiry < minSigExpiry {
		signatureExpiry = minSigExpiry
	}

	return &adminSignatureProtector{
		storage:          storage,
		payloadFormatter: payloadFormatter,
		logger:           slslog.NewWith("admin_protector", true),
		signatureExpiry:  signatureExpiry,
	}
}

func (s *adminSignatureProtector) IsSignatureValid(ctx context.Context, method string, args []any, signature string) (common.Address, bool) {
	now := time.Now().Truncate(time.Minute).UTC()

	for i := float64(0); i <= s.signatureExpiry.Minutes(); i++ {
		finalTime := now.Add(time.Duration(i) * time.Minute * -1)
		addr, isValid := s.verifySignature(ctx, finalTime, method, args, signature)
		if isValid {
			return addr, isValid
		}
	}

	return common.Address{}, false
}

func (s *adminSignatureProtector) verifySignature(ctx context.Context, signTime time.Time, method string, args []any, signature string) (common.Address, bool) {
	// Decode the signature
	sig := common.FromHex(signature)
	if len(sig) != 65 {
		s.logger.With("signature", signature).Warn("Invalid signature length")
		return common.Address{}, false
	}

	// Ethereum signatures uses a "v" value of 27 or 28, which is an offset added to
	// distinguish Ethereum-specific signatures from other ECDSA signatures.
	if sig[64] != 27 && sig[64] != 28 {
		return common.Address{}, false
	}

	// The `crypto.SigToPub` function expects this value to be 0 or 1, so we adjust it
	// here by subtracting 27.
	sig[64] -= 27

	// Format the payload based on the method, args, and time
	payload := s.payloadFormatter.Format(signTime, method, args)
	msgHash := accounts.TextHash([]byte(payload))

	// Recover the public key from the signature
	signerPublicKey, err := crypto.SigToPub(msgHash, sig)
	if err != nil || signerPublicKey == nil {
		s.logger.With("err", err).Warn("Can't extract public key from signature")
		return common.Address{}, false
	}

	// Convert public key to Ethereum address
	signerAddress := crypto.PubkeyToAddress(*signerPublicKey)

	// Check if the signer is an admin
	isAdmin, err := s.storage.IsAdmin(ctx, signerAddress)
	if err != nil {
		s.logger.With("err", err, "signer", signerAddress.String()).Warn("Error while calling IsAdmin to validate signer address")
		return common.Address{}, false
	}

	return signerAddress, isAdmin
}
