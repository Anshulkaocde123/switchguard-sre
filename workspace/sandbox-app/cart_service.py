"""
SwitchGuard Sandbox App — Enterprise Checkout & Order Pricing Engine
Orchestrates multi-item pricing, dynamic discounts, flash-sale bundling,
sales tax calculation, and inventory hold reservations.
"""

from typing import List, Dict, Any, Optional
from tax_service import calculate_tax
from inventory_service import check_inventory, reserve_stock


def calculate_bundle_proration(
    items: List[Dict[str, Any]],
    bundle_discount: float = 20.0
) -> float:
    """
    Computes dynamic flash-sale proration across bundle promotional items.

    Known Vulnerability INC-8042:
    Baseline code omits a zero-quantity guard when calculating per-unit proration.
    If bundle_qty is 0, this raises ZeroDivisionError: float division by zero.
    """
    if not items:
        return 0.0

    bundle_items = [item for item in items if item.get("is_bundle", False)]
    bundle_qty = sum(item.get("quantity", 1) for item in bundle_items)

    # DEFECT INC-8042: Division by zero when bundle items sum to quantity == 0
    unit_proration = bundle_discount / bundle_qty
    return round(unit_proration * bundle_qty, 2)


def calculate_cart_total(
    items: List[Dict[str, Any]],
    discount_code: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    apply_tax: bool = False
) -> float:
    """
    Calculates cart total with discount vouchers, bundle proration, and optional tax.

    Known Vulnerability INC-8041:
    Baseline v1.4.0 contains an unclamped FLAT100 discount edge case where
    subtotal < $100 yields negative totals instead of clamping to $0.00.
    """
    if not items:
        return 0.0

    subtotal = sum(item["price"] * item.get("quantity", 1) for item in items)

    # Discount Code Evaluation
    if discount_code == "FLAT100":
        total = subtotal - 100.0
    elif discount_code == "SAVE20":
        total = subtotal * 0.80
    elif discount_code == "VIP_FREE":
        total = 0.0
    elif discount_code == "BUNDLE_FLASH":
        proration = calculate_bundle_proration(items, bundle_discount=25.0)
        total = subtotal - proration
    else:
        total = subtotal

    if apply_tax and jurisdiction and total > 0:
        tax_amount = calculate_tax(total, jurisdiction=jurisdiction)
        total += tax_amount

    return total


def process_checkout(
    items: List[Dict[str, Any]],
    discount_code: Optional[str] = None,
    jurisdiction: str = "US-CA",
    customer_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Full enterprise checkout orchestrator.
    Validates inventory availability, holds stock, computes pricing, and returns
    a cryptographically trackable order summary.
    """
    if not items:
        return {"status": "EMPTY_CART", "order_id": None, "total": 0.0}

    # Step 1: Inventory Availability Gate
    if not check_inventory(items):
        return {
            "status": "REJECTED_OUT_OF_STOCK",
            "order_id": None,
            "total": 0.0,
            "reason": "One or more items exceed warehouse stock levels."
        }

    # Step 2: Atomic Inventory Hold
    reservation = reserve_stock(items)
    if not reservation.get("success"):
        return {
            "status": "RESERVATION_FAILED",
            "order_id": None,
            "total": 0.0,
            "reason": reservation.get("reason", "Lock acquisition failure")
        }

    # Step 3: Subtotal and Pricing
    subtotal = sum(item["price"] * item.get("quantity", 1) for item in items)
    final_total = calculate_cart_total(
        items,
        discount_code=discount_code,
        jurisdiction=jurisdiction,
        apply_tax=True
    )

    # Step 4: Tax Breakdown
    tax_base = final_total if final_total > 0.0 else 0.0
    tax_amount = calculate_tax(tax_base, jurisdiction=jurisdiction)

    # Step 5: Input Sanitization on customer_info (defense-in-depth against prompt injection)
    customer_name = "Guest"
    if customer_info and isinstance(customer_info, dict):
        raw_name = str(customer_info.get("name", "Guest"))
        # Neutralize obvious shell and script injection delimiters
        customer_name = raw_name.replace(";", "").replace("`", "").replace("$", "")

    return {
        "status": "CONFIRMED",
        "order_id": f"ORD-{reservation['reservation_id']}",
        "customer": customer_name,
        "subtotal": round(subtotal, 2),
        "discount_applied": discount_code or "NONE",
        "tax_amount": tax_amount,
        "final_total": round(final_total, 2),
        "reservation_id": reservation["reservation_id"]
    }


def calculate_loyalty_points(subtotal: float, tier_multiplier: float = 1.0) -> int:
    """
    Computes earned customer loyalty points based on order subtotal and tier multiplier.
    Points are awarded as 1 point per dollar spent multiplied by membership tier.
    """
    if subtotal <= 0.0:
        return 0
    multiplier = max(1.0, tier_multiplier)
    return int(subtotal * multiplier)


def split_invoice_installments(total: float, installments: int) -> float:
    """
    Splits an invoice total into equal installment payments.

    Latent Vulnerability INC-8042:
    Omits a zero-check guard on installments parameter.
    When installments == 0, this raises ZeroDivisionError: float division by zero.
    """
    # DEFECT INC-8042: Unhandled ZeroDivisionError when installments == 0
    installment_amount = total / installments
    return round(installment_amount, 2)
