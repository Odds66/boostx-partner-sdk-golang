package boostx_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
)

// -----------------------------------------------------------------------------
// Integration examples
// -----------------------------------------------------------------------------

// The SDK keys everything by partner_id: register each partner's keys in a
// MemoryKeyStore, and the handlers select the right keys by the token's
// partner_id. These examples register two partners; registering one is the same.

// Example_mount is the simplest integration: MountHandlers registers every
// partner-side endpoint on an *http.ServeMux — POST /set-boost and /verify-keys
// always, plus /check-bet when the store implements BetStoreChecker. The handlers
// look up each request's keys from the store by the token's partner_id.
func Example_mount() {
	bx := newMockBoostxServer()
	keyStore := registerPartners(bx)

	mux := http.NewServeMux()
	boostx.MountHandlers(mux, "/boostx", newExampleBetStore(), keyStore)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Each request is verified with its own partner_id's keys — partner-2's
	// request (signed with a different BoostX key) would fail against partner-1's.
	for _, t := range tenants {
		bx.SetPartnerURL(t.id, server.URL+"/boostx")
		ok, err := bx.VerifyKeys(t.id)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %t\n", t.id, ok)
	}
	// Output:
	// partner-1: true
	// partner-2: true
}

// Example_handlersOnly builds the handlers individually and mounts them on a
// server the partner controls. Each constructor returns an http.Handler, so they
// drop into any router (gin, echo, chi, …); here a standard-library mux.
func Example_handlersOnly() {
	bx := newMockBoostxServer()
	keyStore := registerPartners(bx)
	betStore := newExampleBetStore()

	mux := http.NewServeMux()
	mux.Handle("POST /boostx/set-boost", boostx.NewSetBoostHandler(betStore, keyStore))
	mux.Handle("POST /boostx/verify-keys", boostx.NewVerifyKeysHandler(keyStore))
	mux.Handle("POST /boostx/check-bet", boostx.NewCheckBetHandler(betStore, keyStore))

	server := httptest.NewServer(mux)
	defer server.Close()

	for _, t := range tenants {
		bx.SetPartnerURL(t.id, server.URL+"/boostx")
		ok, err := bx.VerifyKeys(t.id)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %t\n", t.id, ok)
	}
	// Output:
	// partner-1: true
	// partner-2: true
}

// Example_manual hand-writes the /verify-keys handler and selects the
// key set by the partner_id carried in the token. The same Extract → look up
// keys → Parse shape applies to /set-boost and /check-bet (keyed on the partner
// from ExtractBoosterPartner / ExtractCheckBetPartner).
func Example_manual() {
	bx := newMockBoostxServer()
	// Typed as the interface, so the handler can reach only the public methods.
	var keyStore boostx.HandlersKeyStore = registerPartners(bx)

	verifyKeys := func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			VerifyKeysJWT string `json:"verifyKeysJWT"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// The partner_id (the "aud" claim) selects which key set to use; this
		// handler resolves keys through the HandlersKeyStore's public methods,
		// just as the SDK handlers do internally.
		partner, err := boostx.ExtractVerifyKeysRequestPartner(body.VerifyKeysJWT)
		if err != nil {
			http.Error(w, "invalid verifyKeysJWT: "+boostx.VerifyKeysReasonShape, http.StatusBadRequest)
			return
		}
		boostxPub, err := keyStore.BoostxPublicKey(r.Context(), partner)
		if err != nil {
			http.Error(w, "unknown partner", http.StatusNotFound)
			return
		}
		req, err := boostx.ParseVerifyKeysRequestToken(body.VerifyKeysJWT, boostxPub, partner, 0)
		if err != nil {
			http.Error(w, "invalid verifyKeysJWT: "+boostx.VerifyKeysReason(err), http.StatusBadRequest)
			return
		}
		partnerPriv, err := keyStore.PartnerPrivateKey(r.Context(), partner)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		respJWT, err := boostx.CreateVerifyKeysResponseToken(partnerPriv, partner, req.Nonce)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]string{"responseJWT": respJWT},
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /boostx/verify-keys", verifyKeys)
	server := httptest.NewServer(mux)
	defer server.Close()

	for _, t := range tenants {
		bx.SetPartnerURL(t.id, server.URL+"/boostx")
		ok, err := bx.VerifyKeys(t.id)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %t\n", t.id, ok)
	}
	// Output:
	// partner-1: true
	// partner-2: true
}

// Example_outbound creates a signed Settlement token for the right
// partner_id by resolving its key from the MemoryKeyStore the handlers already
// use, then handing it to CreateSettlementToken.
func Example_outbound() {
	store := boostx.NewMemoryKeyStore()
	for _, t := range tenants {
		if err := store.Register(t.id, nil, t.partner, nil); err != nil {
			log.Fatal(err)
		}
	}

	params := boostx.SettlementParams{
		Partner: "partner-1", User: "user-1", Bet: "bet-1",
		Result: "won", Amount: 150, Currency: "USD",
	}
	key, err := store.PartnerPrivateKey(context.Background(), params.Partner)
	if err != nil {
		log.Fatal(err)
	}
	tok, err := boostx.CreateSettlementToken(key, params)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("signed:", tok != "")
	// Output: signed: true
}

// -----------------------------------------------------------------------------
// Test helpers and fixtures
// -----------------------------------------------------------------------------

// mockBoostxServer mocks BoostX's side of the integration. Registering a
// partner_id mints a BoostX key pair for it (as the backend does at partner
// creation) and returns the public key the partner stores; VerifyKeys then
// signs requests with the private key and checks the partner's responses.
type mockBoostxServer struct {
	byPartner map[string]mockPartner
	nonceSeq  int32 // hands out a fresh nonce per VerifyKeys call
}

// mockPartner is one registered partner_id: the BoostX key pair minted for it,
// the partner's public key (to verify responses), and the partner's base URL.
type mockPartner struct {
	url        string
	boostxPriv *ecdsa.PrivateKey
	partnerPub *ecdsa.PublicKey
}

func newMockBoostxServer() *mockBoostxServer {
	return &mockBoostxServer{byPartner: make(map[string]mockPartner)}
}

// AddPartner registers a partner_id: it mints BoostX's key pair for that partner,
// stores the private key, and returns the public key the partner must configure
// to verify inbound BoostX requests.
func (s *mockBoostxServer) AddPartner(partnerID string, partnerPub *ecdsa.PublicKey) *ecdsa.PublicKey {
	boostxKey := newExampleKeyPair()
	s.byPartner[partnerID] = mockPartner{boostxPriv: boostxKey, partnerPub: partnerPub}
	return &boostxKey.PublicKey
}

// SetPartnerURL sets the base URL where a registered partner_id's server can be
// reached. Call it once the partner's server is up — its URL is only known after
// start.
func (s *mockBoostxServer) SetPartnerURL(partnerID, partnerURL string) {
	p, ok := s.byPartner[partnerID]
	if !ok {
		log.Fatalf("mockBoostxServer: unknown partner %q", partnerID)
	}
	p.url = partnerURL
	s.byPartner[partnerID] = p
}

// VerifyKeys runs the verify-keys handshake against partnerID: it signs a request
// carrying a fresh nonce, POSTs it to the partner's registered URL, verifies the
// partner's signed response, and reports whether the partner echoed the nonce
// back (ok). Transport, signing, and parse failures are returned as the error.
func (s *mockBoostxServer) VerifyKeys(partnerID string) (ok bool, err error) {
	p, found := s.byPartner[partnerID]
	if !found {
		return false, fmt.Errorf("unknown partner %q", partnerID)
	}

	s.nonceSeq++
	nonce := s.nonceSeq
	reqJWT, err := boostx.CreateVerifyKeysRequestToken(p.boostxPriv, partnerID, nonce)
	if err != nil {
		return false, err
	}

	body, _ := json.Marshal(map[string]string{"verifyKeysJWT": reqJWT})
	resp, err := http.Post(p.url+"/verify-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var out struct {
		Result struct {
			ResponseJWT string `json:"responseJWT"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}

	vk, err := boostx.ParseVerifyKeysResponseToken(out.Result.ResponseJWT, p.partnerPub, partnerID, 0)
	if err != nil {
		return false, err
	}
	// The partner passes verify-keys only if it echoes our nonce back.
	return vk.Nonce == nonce, nil
}

// exampleBetStore is a partner's bet store. Implementing the optional CheckBet
// method (BetStoreChecker) also enables the /check-bet endpoint.
type exampleBetStore struct{}

// newExampleBetStore returns a no-op bet store that accepts every boost and
// reports every bet active.
func newExampleBetStore() exampleBetStore {
	return exampleBetStore{}
}

func (exampleBetStore) SetBoost(_ context.Context, _ *boostx.Booster) error     { return nil }
func (exampleBetStore) CheckBet(_ context.Context, _ *boostx.GID) (bool, error) { return true, nil }

func newExampleKeyPair() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return k
}

// tenant is one partner_id and its key pair. BoostX mints its own key pair per
// partner_id (see mockBoostxServer.AddPartner), so a tenant carries only the
// partner's keys.
type tenant struct {
	id      string
	partner *ecdsa.PrivateKey
}

// tenants is the shared partner_id set used by the multi-tenant examples.
var tenants = []tenant{
	{id: "partner-1", partner: newExampleKeyPair()},
	{id: "partner-2", partner: newExampleKeyPair()},
}

// registerPartners mints each tenant's BoostX key pair (via the mock) and builds
// the shipped multi-tenant MemoryKeyStore the handlers use.
func registerPartners(bx *mockBoostxServer) *boostx.MemoryKeyStore {
	store := boostx.NewMemoryKeyStore()
	for _, t := range tenants {
		boostxPub := bx.AddPartner(t.id, &t.partner.PublicKey)
		if err := store.Register(t.id, &t.partner.PublicKey, t.partner, boostxPub); err != nil {
			log.Fatal(err)
		}
	}
	return store
}
