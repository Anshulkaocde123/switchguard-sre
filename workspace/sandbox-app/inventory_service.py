"""
SwitchGuard Sandbox App — Inventory Service Module
Manages stock validation, warehouse availability checks, and order reservations.
"""

from typing import Dict, List, Any
import uuid

# In-memory warehouse inventory catalogue
INVENTORY_CATALOG: Dict[str, Dict[str, Any]] = {
    "SKU-DEV-KEYBOARD": {"name": "Mechanical Keyboard", "stock": 45, "price": 120.0},
    "SKU-DEV-MOUSE": {"name": "Precision Mouse", "stock": 80, "price": 60.0},
    "SKU-DEV-MONITOR": {"name": "4K Monitor", "stock": 15, "price": 350.0},
    "SKU-DEV-CABLE": {"name": "USB-C Braided Cable", "stock": 250, "price": 15.0},
    "SKU-BUNDLE-KIT": {"name": "Full Dev Setup Bundle", "stock": 10, "price": 450.0},
}

_ACTIVE_RESERVATIONS: Dict[str, List[Dict[str, Any]]] = {}


def get_stock(sku: str) -> int:
    """Returns available warehouse stock quantity for a given SKU."""
    item = INVENTORY_CATALOG.get(sku)
    return item["stock"] if item else 0


def check_inventory(items: List[Dict[str, Any]]) -> bool:
    """
    Validates whether all requested cart items are currently in stock.
    Items without explicit SKU default to in-stock pass-through.
    """
    for item in items:
        sku = item.get("sku")
        if not sku:
            continue
        qty = item.get("quantity", 1)
        if get_stock(sku) < qty:
            return False
    return True


def reserve_stock(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Creates an atomic inventory hold for a checkout session.
    Returns reservation metadata or failure status.
    """
    if not check_inventory(items):
        return {"success": False, "reservation_id": None, "reason": "INSUFFICIENT_STOCK"}

    reservation_id = f"RES-{uuid.uuid4().hex[:8].upper()}"
    reserved_items = []
    for item in items:
        sku = item.get("sku")
        qty = item.get("quantity", 1)
        if sku and sku in INVENTORY_CATALOG:
            INVENTORY_CATALOG[sku]["stock"] -= qty
            reserved_items.append({"sku": sku, "quantity": qty})

    _ACTIVE_RESERVATIONS[reservation_id] = reserved_items
    return {"success": True, "reservation_id": reservation_id, "items": reserved_items}


def release_stock(reservation_id: str) -> bool:
    """Releases a reserved inventory hold back to available catalog stock."""
    reserved = _ACTIVE_RESERVATIONS.pop(reservation_id, None)
    if not reserved:
        return False

    for item in reserved:
        sku = item["sku"]
        if sku in INVENTORY_CATALOG:
            INVENTORY_CATALOG[sku]["stock"] += item["quantity"]
    return True
