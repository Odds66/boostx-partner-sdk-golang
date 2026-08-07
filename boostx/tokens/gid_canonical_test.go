package tokens

import "testing"

// TestCanonicalGIDPayloadMatchesJSONStringify pins the GID signing bytes against the
// encoder BoostX actually verifies with: JavaScript's JSON.stringify. The `want` values
// were produced by real Node, so they are evidence, not a restatement of the package.
// Printable characters appear literally, checkable by eye; invisible ones (C0 controls,
// U+2028/U+2029) are written as escapes. See canonicalGIDPayload for why encoding/json
// cannot produce these bytes and why only this table can catch a divergence.
func TestCanonicalGIDPayloadMatchesJSONStringify(t *testing.T) {
	tests := []struct {
		name    string
		partner string
		user    string
		bet     string
		want    string
	}{
		{
			name:    "plain",
			partner: "acme",
			user:    "u1",
			bet:     "b1",
			want:    `{"partner":"acme","user":"u1","bet":"b1"}`,
		},
		{
			name:    "ampersand",
			partner: "acme&co",
			user:    "u&1",
			bet:     "b&1",
			want:    `{"partner":"acme&co","user":"u&1","bet":"b&1"}`,
		},
		{
			name:    "angle_brackets",
			partner: "a<b>c",
			user:    "u<1>",
			bet:     "b>2",
			want:    `{"partner":"a<b>c","user":"u<1>","bet":"b>2"}`,
		},
		{
			name:    "quote_and_backslash",
			partner: `a"b`,
			user:    `u\1`,
			bet:     `b"2`,
			want:    `{"partner":"a\"b","user":"u\\1","bet":"b\"2"}`,
		},
		{
			// Raw-string want: the escape text JSON.stringify emits, not the characters.
			name:    "control_chars",
			partner: "a\nb",
			user:    "u\tv",
			bet:     "b\r",
			want:    `{"partner":"a\nb","user":"u\tv","bet":"b\r"}`,
		},
		{
			// Interpreted-string want: JSON.stringify leaves U+2028/U+2029 literal.
			name:    "line_separators",
			partner: "a\u2028b",
			user:    "u\u2029v",
			bet:     "bet",
			want:    "{\"partner\":\"a\u2028b\",\"user\":\"u\u2029v\",\"bet\":\"bet\"}",
		},
		{
			name:    "other_c0",
			partner: "a\u0001b",
			user:    "u\u001fv",
			bet:     "b",
			want:    `{"partner":"a\u0001b","user":"u\u001fv","bet":"b"}`,
		},
		{
			name:    "cyrillic",
			partner: "акме",
			user:    "пол",
			bet:     "ст",
			want:    `{"partner":"акме","user":"пол","bet":"ст"}`,
		},
		{
			name:    "astral",
			partner: "a😀b",
			user:    "u😀",
			bet:     "b",
			want:    `{"partner":"a😀b","user":"u😀","bet":"b"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(canonicalGIDPayload(tt.partner, tt.user, tt.bet))
			if got != tt.want {
				t.Errorf("canonical payload diverges from JSON.stringify\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestGIDRoundTripSurvivesHTMLSensitiveCharacters checks ids with the once-mis-escaped
// characters verify end to end. Build and verify share the encoder, so only the pinned
// table above — not this test — can catch an encoding regression.
func TestGIDRoundTripSurvivesHTMLSensitiveCharacters(t *testing.T) {
	priv, pub := generateTestKey(t)

	for _, id := range []string{"acme&co", "u<1>", "a\u2028b"} {
		t.Run(id, func(t *testing.T) {
			gid, err := BuildGID("partner", id, "bet-"+id, priv)
			if err != nil {
				t.Fatalf("BuildGID: %v", err)
			}
			if err := VerifyGID(gid, pub); err != nil {
				t.Errorf("VerifyGID: %v", err)
			}
		})
	}
}
