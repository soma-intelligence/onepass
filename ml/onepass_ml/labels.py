"""Label set of the field classifiers: the lab Role list plus "none".

Same names, same order as `Role` in extension/lab/gen/model.ts (tests/test_labels.py parses that
file, so a drift fails CI). The index of a label here is the class index of every model.
"""

from __future__ import annotations

ROLES = (
    "username", "email", "password", "new_password", "otp", "cc_name", "cc_number", "cc_exp",
    "cc_exp_month", "cc_exp_year", "cc_csc", "given_name", "family_name", "tel", "birth_date",
    "organization", "address_line1", "address_line2", "postal_code", "city", "country",
)
LABELS = ROLES + ("none",)
