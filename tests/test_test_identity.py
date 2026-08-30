import pytest
import pickle

from argus.models.test_identity import TestIdentity, AuthType
from argus.runtime.mission import Mission


def test_test_identity_defaults_and_post_init():
    ident = TestIdentity(name="Alice", role="admin")
    assert ident.id is not None
    assert ident.name == "Alice"
    assert ident.role == "admin"
    assert ident.roles == ["admin"]
    assert ident.auth_type == AuthType.NONE
    assert ident.is_active is True


def test_test_identity_bearer_auth_headers():
    ident = TestIdentity(
        name="API User",
        auth_type=AuthType.BEARER,
        token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    )
    headers = ident.get_auth_headers()
    assert headers["Authorization"] == "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."


def test_test_identity_basic_auth_headers():
    ident = TestIdentity(
        name="Basic User",
        auth_type=AuthType.BASIC,
        credentials={"username": "admin", "password": "secretpassword123"},
    )
    headers = ident.get_auth_headers()
    assert headers["Authorization"].startswith("Basic ")


def test_test_identity_api_key_auth_headers():
    ident = TestIdentity(
        name="Key User",
        auth_type=AuthType.API_KEY,
        credentials={"api_key": "argus_live_key_998877", "key_header": "X-Custom-API-Key"},
    )
    headers = ident.get_auth_headers()
    assert headers["X-Custom-API-Key"] == "argus_live_key_998877"


def test_test_identity_oauth2_auth_headers():
    ident = TestIdentity(
        name="OAuth User",
        auth_type=AuthType.OAUTH2,
        token="ya29.a0AfH6SM...",
    )
    headers = ident.get_auth_headers()
    assert headers["Authorization"] == "Bearer ya29.a0AfH6SM..."


def test_test_identity_custom_and_none_auth_headers():
    ident_none = TestIdentity(name="Guest", auth_type=AuthType.NONE)
    assert ident_none.get_auth_headers() == {}

    ident_custom = TestIdentity(
        name="Custom Auth",
        auth_type=AuthType.CUSTOM,
        headers={"X-Token": "xyz123", "X-Tenant-ID": "tenant_1"},
    )
    headers = ident_custom.get_auth_headers()
    assert headers["X-Token"] == "xyz123"
    assert headers["X-Tenant-ID"] == "tenant_1"


def test_test_identity_cookies_and_session_update():
    ident = TestIdentity(
        name="Cookie User",
        auth_type=AuthType.COOKIE,
        cookies={"sessionid": "sess_112233"},
    )
    assert ident.get_cookies() == {"sessionid": "sess_112233"}

    ident.update_session(
        cookies={"csrf_token": "csrf_aabbcc"},
        token="new_token_value",
    )
    assert ident.cookies["sessionid"] == "sess_112233"
    assert ident.cookies["csrf_token"] == "csrf_aabbcc"
    assert ident.token == "new_token_value"


def test_test_identity_to_dict_and_from_dict_roundtrip():
    ident = TestIdentity(
        name="Serialized User",
        role="tester",
        roles=["tester", "qa"],
        auth_type=AuthType.BEARER,
        credentials={"username": "user1"},
        headers={"X-Test": "1"},
        cookies={"s": "2"},
        token="tok_123",
        login_url="https://app.com/login",
        login_payload={"u": "1", "p": "2"},
        login_type="json",
    )

    data = ident.to_dict()
    assert data["name"] == "Serialized User"
    assert data["auth_type"] == "BEARER"

    rebuilt = TestIdentity.from_dict(data)
    assert rebuilt.id == ident.id
    assert rebuilt.name == ident.name
    assert rebuilt.auth_type == AuthType.BEARER
    assert rebuilt.roles == ["tester", "qa"]
    assert rebuilt.token == "tok_123"
    assert rebuilt.login_url == "https://app.com/login"


def test_test_identity_clone():
    original = TestIdentity(
        name="Original",
        role="admin",
        auth_type=AuthType.BEARER,
        token="tok_original",
    )
    cloned = original.clone(name="Cloned", token="tok_cloned")
    assert cloned.id != original.id
    assert cloned.name == "Cloned"
    assert cloned.role == "admin"
    assert cloned.token == "tok_cloned"


def test_mission_test_identities_crud_and_active_switching():
    mission = Mission(target="example.com")
    assert mission.test_identities == []
    assert mission.get_active_identity() is None

    id1 = TestIdentity(name="Admin User", role="admin", auth_type=AuthType.BEARER, token="admin_tok")
    id2 = TestIdentity(name="Standard User", role="user", auth_type=AuthType.COOKIE, cookies={"s": "1"})

    mission.add_test_identity(id1)
    assert len(mission.test_identities) == 1
    assert mission.get_active_identity().name == "Admin User"
    assert mission.active_identity_id == id1.id

    mission.add_test_identity(id2)
    assert len(mission.test_identities) == 2

    # Switch active identity
    mission.set_active_identity(id2.id)
    assert mission.get_active_identity().name == "Standard User"

    # Lookup by name
    found = mission.get_test_identity("Admin User")
    assert found is not None
    assert found.id == id1.id

    # List
    all_idents = mission.list_test_identities()
    assert len(all_idents) == 2

    # Clear
    mission.clear_test_identities()
    assert len(mission.test_identities) == 0
    assert mission.get_active_identity() is None


def test_mission_pickle_serialization_with_test_identities():
    mission = Mission(target="target.com")
    ident = TestIdentity(name="PickleUser", role="admin", auth_type=AuthType.BEARER, token="secure_token_123")
    mission.add_test_identity(ident)

    pickled_data = pickle.dumps(mission)
    unpickled_mission = pickle.loads(pickled_data)

    assert unpickled_mission.target == "target.com"
    assert len(unpickled_mission.test_identities) == 1
    assert unpickled_mission.test_identities[0].name == "PickleUser"
    assert unpickled_mission.test_identities[0].auth_type == AuthType.BEARER
    assert unpickled_mission.test_identities[0].token == "secure_token_123"
    assert unpickled_mission.get_active_identity().name == "PickleUser"
