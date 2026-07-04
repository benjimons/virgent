"""Identity security: IdP posture and access reviews.

Reads an identity provider (Okta, Entra ID, Google Workspace) with read-only
credentials and enumerates its accounts, groups, and privileged assignments —
the same insider view a network scan can never reach. The identity posture
capability then flags the classic IAM weaknesses (missing MFA, dormant
accounts, over-broad admin, stale credentials), and the access-review
generator produces recertification campaigns for control owners.

Providers are injectable (``MockIdentityProvider`` for offline tests), so
nothing here needs credentials or the network to be importable or tested.
"""
from .providers import (
    IdentityProvider,
    IdentityAccount,
    MockIdentityProvider,
    OktaProvider,
    build_identity_provider,
)
from .reviews import AccessReview, generate_access_reviews

__all__ = [
    "IdentityAccount",
    "IdentityProvider",
    "MockIdentityProvider",
    "OktaProvider",
    "build_identity_provider",
    "AccessReview",
    "generate_access_reviews",
]
