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
| 2026-11-05 16:32:20 UTC | `INC-9001` | `NEGATIVE_TOTAL_CALCULATION` | 1 | `2eca72a8baaa...` | [CRITICAL] CartServiceException in cart_service.py line 5 User: [REDACTED_EMAIL] FLAT100 -0.00 |
| 2026-11-05 16:32:20 UTC | `INC-9002` (SPIKE #2) | `NEGATIVE_TOTAL_CALCULATION` | 1 | `2eca72a8baaa...` | [SUPPRESSED SPIKE #2] [CRITICAL] CartServiceException in cart_service.py line 5 User: [REDACTED_EMAIL] FLAT100 -0.00 |
| 2026-11-05 16:34:22 UTC | `INC-DEMO-1` (SPIKE #3) | `NEGATIVE_TOTAL_CALCULATION` | 1 | `2eca72a8baaa...` | [SUPPRESSED SPIKE #3] [CRITICAL] CartServiceException in cart_service.py line 5 User: [REDACTED_EMAIL] FLAT100 -0.00 |
