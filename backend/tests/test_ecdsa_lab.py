import pytest
from backend.core import ecdsa_lab as L

M1, M2 = b"transfer 10 to alice", b"transfer 9999 to mallory"


def test_curve_constants_consistent_with_openssl():
    assert L.nonce_to_r(1) == 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296  # Gx
    L.nonce_to_r(L.N - 1)
    with pytest.raises(ValueError):
        L.nonce_to_r(L.N)


def test_custom_signature_math_verifies_with_openssl():
    key = L.new_test_key()
    for _ in range(20):
        r, s = L.educational_sign_with_nonce(key, M1, L.random_nonce())
        assert L.verify(key.public_key(), M1, r, s)
        assert not L.verify(key.public_key(), M2, r, s)


def test_secure_and_deterministic_signatures_verify():
    key = L.new_test_key()
    pub = key.public_key()
    r, s = L.library_sign(key, M1)
    assert L.verify(pub, M1, r, s)
    d1, d2 = L.library_sign(key, M1, True), L.library_sign(key, M1, True)
    assert d1 == d2 and L.verify(pub, M1, *d1)          # RFC 6979: same message -> same signature
    assert L.library_sign(key, M1, True) != L.library_sign(key, M2, True)


def test_normal_signing_never_repeats_r():
    key = L.new_test_key()
    sigs = [{"id": i, "key_id": "k", "r": L.library_sign(key, f"m{i}".encode())[0], "s": 1} for i in range(60)]
    assert L.detect_nonce_reuse(sigs) == []


def test_reuse_detected_and_key_recovered_and_verified():
    key = L.new_test_key()
    pub = key.public_key()
    k = L.random_nonce()
    s1 = L.educational_sign_with_nonce(key, M1, k)
    s2 = L.educational_sign_with_nonce(key, M2, k)
    assert L.verify(pub, M1, *s1) and L.verify(pub, M2, *s2)
    assert s1[0] == s2[0]
    det = L.detect_nonce_reuse([{"id": "a", "key_id": "k", "r": s1[0], "s": s1[1]}, {"id": "b", "key_id": "k", "r": s2[0], "s": s2[1]}])
    assert len(det) == 1
    res = L.recover_private_key(pub, M1, s1, M2, s2)
    assert res["recovered"] and res["d"] == L.private_value(key)
    from cryptography.hazmat.primitives.asymmetric import ec
    assert ec.derive_private_key(res["d"], L.CURVE).public_key().public_numbers() == pub.public_numbers()


def test_recovery_handles_low_s_normalised_signature():
    key = L.new_test_key()
    k = L.random_nonce()
    s1 = L.educational_sign_with_nonce(key, M1, k)
    r, s2 = L.educational_sign_with_nonce(key, M2, k)
    res = L.recover_private_key(key.public_key(), M1, s1, M2, (r, L.N - s2))
    assert res["recovered"] and res["d"] == L.private_value(key) and res["variant"] == "n-s2"


def test_recovery_fails_without_shared_nonce_or_with_same_message():
    key = L.new_test_key()
    pub = key.public_key()
    a, b = L.library_sign(key, M1), L.library_sign(key, M2)
    assert not L.recover_private_key(pub, M1, a, M2, b)["recovered"]
    k = L.random_nonce()
    s = L.educational_sign_with_nonce(key, M1, k)
    assert not L.recover_private_key(pub, M1, s, M1, s)["recovered"]


def test_recovery_rejects_wrong_public_key():
    key, other = L.new_test_key(), L.new_test_key()
    k = L.random_nonce()
    s1, s2 = L.educational_sign_with_nonce(key, M1, k), L.educational_sign_with_nonce(key, M2, k)
    assert not L.recover_private_key(other.public_key(), M1, s1, M2, s2)["recovered"]


def test_session_recovery_and_no_secret_exposure():
    s = L.create_session()
    k = L.random_nonce()
    for m in (M1, M2):
        r, sv = L.educational_sign_with_nonce(s.key, m, k)
        assert L.add_signature(s, m, r, sv, "EDUCATIONAL")["verified"]
    res = L.do_recover(s)
    assert res["recovered"] and res["matches_original"] and res["forgery_verifies"] and res["public_key_check"]
    d_hex = f"{L.private_value(s.key):064x}"
    assert d_hex not in str(L.session_view(s)) and d_hex not in str(res)


def test_faulty_source_modes():
    h = L.FaultyNonceSource("healthy")
    assert len({h.next() for _ in range(50)}) == 50
    st = L.FaultyNonceSource("stuck")
    assert len({st.next() for _ in range(10)}) == 1
    with pytest.raises(ValueError):
        L.FaultyNonceSource("bogus")
