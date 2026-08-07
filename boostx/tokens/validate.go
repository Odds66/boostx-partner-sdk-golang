package tokens

import "math"

// nonNegativeFinite reports whether v is a finite number >= 0 — the shared
// rule for monetary amounts and coefficients. NaN and ±Inf are rejected.
func nonNegativeFinite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0
}

// validCurrencyCode reports whether s is 3 or 4 uppercase ASCII letters — the
// accepted shape for a currency code, e.g. "USD" or "USDT".
func validCurrencyCode(s string) bool {
	if len(s) < 3 || len(s) > 4 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}
