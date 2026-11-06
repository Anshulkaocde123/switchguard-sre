"""
SwitchGuard Sandbox App — Sales Tax Service Module
Handles regional and international jurisdiction sales tax calculations.
"""

from typing import Dict

# Standard tax rate tables by jurisdiction
JURISDICTION_RATES: Dict[str, float] = {
    "US-CA": 0.0825,   # California: 8.25%
    "US-NY": 0.08875,  # New York: 8.875%
    "US-TX": 0.0625,   # Texas: 6.25%
    "US-WA": 0.0650,   # Washington: 6.50%
    "EU-VAT": 0.2000,  # European Union Standard VAT: 20.0%
    "EXEMPT": 0.0000,  # Tax Exempt Customers / Non-profits: 0.0%
}


def get_tax_rate(jurisdiction: str) -> float:
    """Returns the applicable sales tax rate for the specified jurisdiction code."""
    if not jurisdiction:
        return 0.0
    return JURISDICTION_RATES.get(jurisdiction.upper(), 0.0)


def calculate_tax(
    subtotal: float,
    jurisdiction: str = "US-CA",
    tax_exempt: bool = False
) -> float:
    """
    Calculates applicable tax rounded to two decimal places.
    Tax cannot be calculated on negative subtotals.
    """
    if subtotal <= 0.0 or tax_exempt:
        return 0.0

    rate = get_tax_rate(jurisdiction)
    return round(subtotal * rate, 2)
