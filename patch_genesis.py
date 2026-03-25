#!/usr/bin/env python3
"""
Patch genesis-params.json with new loan flag, credit history, content pruning,
payment tracking, and jurisdiction fields.
"""
import json

GENESIS_FILE = "/home/josep/chronx/genesis-params.json"

with open(GENESIS_FILE, "r") as f:
    p = json.load(f)

# Verify existing fields
for k in ["loan_warn_principal_usd", "privacy_send_enabled", "jurisdiction_enforcement_enabled"]:
    assert k in p, f"Missing expected field: {k}"

# New loan flag system
p["loan_flags_enabled"] = True
p["loan_flag_governance_wallet_required_for"] = ["Frozen", "UnderReview"]

# Credit history publication — ALL OFF
p["loan_child_chain_publish_enabled"] = False
p["loan_child_chain_default_visibility"] = "private"
p["loan_child_chain_lender_can_publish"] = False
p["loan_child_chain_borrower_can_dispute"] = False
p["loan_child_chain_mutual_seal_enabled"] = False
p["loan_publish_allowed_jurisdictions"] = []
p["loan_publish_blocked_jurisdictions"] = []
p["loan_publish_jurisdiction_change_grace_days"] = 30
p["loan_publish_consent_required_after_unpublish"] = True

# Content pruning — ALL OFF
p["content_pruning_enabled"] = False
p["prune_memo_after_days"] = None
p["prune_email_hash_after_claimed"] = False
p["prune_superseded_flags_after_days"] = None
p["prune_loan_payment_detail_after_days"] = None

# Payment tracking
p["loan_payment_tracking_unit"] = "periods"
p["loan_child_chain_enabled"] = True
p["loan_summary_anchor_on_close"] = True

# Jurisdiction additions
p["jurisdiction_oracle_url"] = "https://chronx.io/jurisdiction-rules.json"
p["jurisdiction_oracle_cache_seconds"] = 86400

with open(GENESIS_FILE, "w") as f:
    json.dump(p, f, indent=2)
    f.write("\n")

print(f"Genesis params updated. Total keys: {len(p)}")
print("SUCCESS: genesis-params.json patched")
