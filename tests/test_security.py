"""
Security tests for Meridian Expenses access control and business logic.

Parametrized from tests/policy.yaml with CWE/WSTG mapping.
Run with: pytest tests/test_security.py -v --tb=short
"""
import os
import yaml
import pytest
from app import app


@pytest.fixture
def client():
    """Flask test client with throwaway database."""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client


@pytest.fixture
def policies():
    """Load policy matrix from YAML."""
    policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
    with open(policy_path) as f:
        return yaml.safe_load(f)["policies"]


def login_user(client, username, password):
    """Helper to log in a user and return session cookie."""
    if not username:
        return None
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False
    )


def make_request(client, method, path, data=None, follow_redirects=False):
    """Make HTTP request with given method."""
    if method == "GET":
        return client.get(path, follow_redirects=follow_redirects)
    elif method == "POST":
        return client.post(path, data=data, follow_redirects=follow_redirects)
    else:
        raise ValueError(f"Unsupported method: {method}")


@pytest.mark.parametrize("policy", [
    pytest.param(p, id=p["id"]) for p in yaml.safe_load(
        open(os.path.join(os.path.dirname(__file__), "policy.yaml"))
    )["policies"]
])
def test_access_control(policy, client):
    """Test access control policies from policy.yaml."""
    # For anonymous tests, use a fresh client and don't follow redirects
    if not policy.get("user"):
        # Fresh client for anonymous requests
        with app.test_client() as test_client:
            resp = make_request(
                test_client,
                policy["method"],
                policy["path"],
                data=policy.get("data"),
                follow_redirects=False  # Don't follow for 302 checks
            )
    else:
        # Login if user specified
        resp = login_user(client, policy["user"], policy["password"])
        assert resp.status_code in (302, 200), f"Login failed for {policy['user']}"

        # Make the actual request
        resp = make_request(
            client,
            policy["method"],
            policy["path"],
            data=policy.get("data"),
            follow_redirects=True
        )

    # Check status code
    assert resp.status_code == policy["expected_status"], (
        f"{policy['id']}: Expected status {policy['expected_status']}, "
        f"got {resp.status_code} for {policy['method']} {policy['path']}"
    )

    # Check body content
    body = resp.get_data(as_text=True)

    for text in policy.get("expected_contains", []):
        assert text in body, (
            f"{policy['id']}: Expected '{text}' in response body for "
            f"{policy['method']} {policy['path']}"
        )

    for text in policy.get("expected_not_contains", []):
        assert text not in body, (
            f"{policy['id']}: Unexpected '{text}' in response body for "
            f"{policy['method']} {policy['path']}"
        )

    # Verify CWE/WSTG mapping is present for audit trail
    if policy.get("cwe"):
        assert policy["cwe"].startswith("CWE-"), f"{policy['id']}: Invalid CWE format"
    if policy.get("wstg"):
        assert policy["wstg"].startswith("WSTG-"), f"{policy['id']}: Invalid WSTG format"


def test_claim_count_unchanged_on_unauthenticated_post(client):
    """AC-05: Verify DB row count unchanged when anon tries to create claim."""
    # Get initial claim count
    with app.app_context():
        from app import db
        initial_count = db().execute("SELECT COUNT(*) FROM claims").fetchone()[0]

    # Try to create claim as anonymous
    resp = client.post("/claim/new", data={
        "merchant": "Test",
        "amount": "100",
        "note": "Test"
    }, follow_redirects=False)

    # Should redirect to login
    assert resp.status_code == 302

    # Verify count unchanged
    with app.app_context():
        from app import db
        final_count = db().execute("SELECT COUNT(*) FROM claims").fetchone()[0]

    assert final_count == initial_count, (
        f"Claim count changed from {initial_count} to {final_count} "
        "after unauthenticated POST"
    )


def test_receipt_path_traversal_blocked(client):
    """AC-06: Verify path traversal attempt returns 403 and doesn't leak source."""
    login_user(client, "jdoe", "password1")

    resp = client.get("/receipt?f=../app.py", follow_redirects=True)
    assert resp.status_code == 403

    body = resp.get_data(as_text=True)
    # Source code should not be in response
    assert "Flask" not in body
    assert "import" not in body
    assert "secret_key" not in body