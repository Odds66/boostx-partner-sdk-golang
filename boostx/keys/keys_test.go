package keys_test

import (
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/client"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
)

// Compile-time proof MemoryKeyStore satisfies both key-store interfaces. These
// live in an external test package because handlers imports keys (for
// ErrUnknownPartner), so an internal-test import of handlers would cycle.
var (
	_ handlers.KeyStore = (*keys.MemoryKeyStore)(nil)
	_ client.KeyStore   = (*keys.MemoryKeyStore)(nil)
)
