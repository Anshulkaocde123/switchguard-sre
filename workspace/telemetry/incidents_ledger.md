# Incident Ledger

## Incident INC-8041

- **Timestamp**: 2026-11-05T12:45:00Z
- **Severity**: High
- **Classification**: NEGATIVE_TOTAL_CALCULATION
- **Status**: Sanitized & Triaged
- **Component**: `cart_service.py` (line 5)

### Reproduction Parameters
- **Discount Code**: `FLAT100`
- **Subtotal**: $40.00 (e.g., `items = [{"price": 40.0, "quantity": 1}]`)
- **Observed Result**: -$60.00
- **Expected Result**: Total clamped to 0.0 (non-negative)

### Sanitized Telemetry Log
```text
[CRITICAL] CartServiceException in cart_service.py line 5
User: [REDACTED_EMAIL]
Auth: [REDACTED_AUTH_TOKEN]
Details: Applying voucher FLAT100 on a $40 order reduced total to -$60.00.
```
| 2026-11-05 15:27:23 UTC | `INC-8041` | `NEGATIVE_TOTAL_CALCULATION` | 2 | `a7a31148dc23...` | Bearer [REDACTED_AUTH_TOKEN] [REDACTED_EMAIL] FLAT100 -0.00 |
| 2026-11-05 17:14:34 UTC | `INC-TEST-01` | `NEGATIVE_TOTAL_CALCULATION` | 2 | `182b6411155c...` | Bearer [REDACTED_AUTH_TOKEN] [REDACTED_EMAIL_973dfe] FLAT100 -0.00 |
| 2026-11-05 17:16:09 UTC | `INC-8042` (SPIKE #2) | `NEGATIVE_TOTAL_CALCULATION` | 1 | `8a1f283140fa...` | [SUPPRESSED SPIKE #2] Bearer [REDACTED_AUTH_TOKEN] FLAT100 -0.00 cart_service.py line 5 |
| 2026-11-05 17:16:49 UTC | `INC-8044` (SPIKE #3) | `NEGATIVE_TOTAL_CALCULATION` | 0 | `17848be7477d...` | [SUPPRESSED SPIKE #3] [CRITICAL] Checkout total calculation error with FLAT100 discount coupon in cart_service.py:5 total -$50.00 |
| 2026-11-05 17:18:54 UTC | `INC-8044` (SPIKE #3) | `NEGATIVE_TOTAL_CALCULATION` | 0 | `17848be7477d...` | [SUPPRESSED SPIKE #3] [CRITICAL] Checkout total calculation error with FLAT100 discount coupon in cart_service.py:5 total -$50.00 |
