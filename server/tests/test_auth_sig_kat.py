#!/usr/bin/env python3
"""
Cross-language Known-Answer Test for the V2 auth / rotation / enrollment
signatures (domain tags 0x01 / 0x02 / 0x03), symmetric companion to the
report-sig KAT (0x07 / 0x08) in ``server/tests/test_report_sig_kat.py``.

Never re-sign these vectors from Python to turn a red test green (WP-E1). They
are produced by the Rust source of truth — the KAT in
``crypto-rs/core/tests/auth_sig_kat.rs`` (fixed mnemonic ``MN_FIXED``, the
enroll -> auth(slot 0) -> rotate(slot 1) flow) — and pinned there as ``EXP_*``
too. On a DELIBERATE change, re-run that Rust test with ``--nocapture`` and copy
the printed values into both files. Re-signing them here makes the KAT
tautological.

Nothing else would catch the drift, and until WP-E1 added this KAT that
Rust<->relay byte-parity was only ever checked by hand. The diff-fuzz corpus is
a Kotlin<->Rust boundary differential that never leaves the FFI, and the route
tests (test_e2e_v2.py) sign in Python with the server's own signature_domain
constants. A one-sided change — a different domain tag, a different message
layout (the ``ts`` width / endianness, the concat order), a different key
derivation on one side only — therefore round-trips green in both suites while
breaking every real login and rotation in production on a bare 401
(``Invalid ephemeral signature`` on verify, ``Rotation rejected`` on
rotate-batch). So the assertions below feed the relay's own verify helper the
exact Rust-produced bytes, against the messages it rebuilds itself: if either
side drifts, one side goes red.

The three signatures are the live V2 auth contract the relay verifies in
``app/routes/auth_v2.py``:

  - 0x01 AuthChallenge : an ephemeral slot signs ``nonce || ts_be_u64``
    (POST /auth/v2/verify).
  - 0x02 BatchRotation : an ephemeral slot signs ``concat(50 new pk)``
    (POST /auth/v2/rotate-batch).
  - 0x03 Enrollment    : the long-term key signs ``concat(50 batch_0 pk)``
    (POST /auth/v2/enroll).
"""

import hashlib
import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-do-not-use"
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))

from app import signature_domain  # noqa: E402
from app.routes import auth_v2  # noqa: E402

# --- Vectors produced by crypto-rs/core/tests/auth_sig_kat.rs (MN_FIXED) ------
# MUST stay byte-identical to the EXP_* constants in that Rust KAT.

# 0x01 AuthChallenge: an ephemeral slot (batch_0 slot 0) signs nonce || ts.
KAT_NONCE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
KAT_TS = 1700000000
SLOT0_PK = "7e8650d32c0d2797e22f8070711abdc6ddeb4e98ea1e0848f250ba845f3a17f5"
AUTH_SIG = (
    "34d773b2b2567a1ec97a0781a8f98a3ac6eb7532f14c7ab48ac0689aaeca6811"
    "eace91c27390050869b95f9628ecc48eacffbc092f7e2ffd8e129e8b2a36ba0d"
)

# 0x03 Enrollment: the long-term identity key signs concat(50 batch_0 pk).
LTK_PK = "f373b6de310a66e4b4f0e1ab355c89446762b59b47895d2d42ecfa5ed8d36920"
ENROLL_SIG = (
    "de566cdb5ef4c2c9f72e65840bfb659d001b3be2c04ef89f616da8323f66eec9"
    "b401b89e8a8794aa4dde3a1606a74ab79d67321065fa5783b1af33b014021f0e"
)
BATCH0_CONCAT_SHA256 = (
    "098e921e1314168f910c1f9db5b80028d97180722fdabdbc1d891418e4b89dd2"
)

# 0x02 BatchRotation: the next slot (batch_0 slot 1) signs concat(50 batch_1 pk).
SIGNER_PK = "17e0116700e346955a96e84617c70662ecef062105d427c6ebff6f319636430a"
ROTATION_SIG = (
    "a4eb59d61f4494eba107b7223d43b3b763d474c9a291de3763a21e10eebe7818"
    "cdeed5388f29b968f89ec1c98c5e6af8a1644e65909a737f9c16e778d4a65308"
)
BATCH1_CONCAT_SHA256 = (
    "df92598ba7ccdd766835bcf5f2754bced587f969eabd9ad5b97dda093cc0b7c4"
)

# The full 1600-byte concat messages for 0x02 / 0x03. Ed25519 verification needs
# the exact bytes, so they are pinned here (the verifier holds no ratchet). Each
# is cross-checked against the compact SHA-256 the Rust KAT pins, so a stale or
# mistyped concat here fails before any signature check — that digest ties this
# big vector to the Rust source of truth on both sides.
BATCH0_CONCAT = (
    "7e8650d32c0d2797e22f8070711abdc6ddeb4e98ea1e0848f250ba845f3a17f517e0116700e346955a96e84617c70662ecef062105d427c6ebff6f319636430adc93f16c7a6b7086800592dd6247642232ca9a412adb8631eb8646d4741d073e1ed94ebd299095bb167f5ff8a66280960837e39622bc7f9cefa7a44c91b3b8c52c30391f57c685ad0b7c7d0d65aa515f6bf4e874644a92f38791a07ab297fe851550f6e900918d8a21f2b4b916fd1a52c2a207006c2f46e9a154c890930ebb01768c98fb387b7e3eed6fa579dc6768edb53a28a17cb43b9c5ce1e499a82778e7e2bb5ac52d9a38441376184b5426949f1cdc8564cf3c82e97e85a1aeab371dcdf5427be8908d426055ee7b2209c865dac232c19b6e2cb6b67901e69f8f03f734d9d4c726b4292dad771ceebea615838993808efe1d8249b153c7bab6b9f85a67b2cb660484d31535026ceacbfa62d467519158e6b14cb89e26e3c1175c9c412ea4e9eeb6144c8552236422d0da42d5144faad69095fd7f98ff7628e32d32d0fa5e715feb261a6d936f4ee3f75927de3113765872ae9c24a493363d68c9596b89d9af715450810038b8189ddef906459d0e0332e0dc35888b6d5ecbc4c89a2498180de57964b13e809d6cc3e560e92da9674943aa45591be85202c76343e752c20768fba16e298f2feb1d2f24601cc5e775941b68a4ab866c20a71fca0d12172be28d00b18e518af7d556c2e04620903ec46aa709eab94976fd5858fa3f02c7f751909ed554b8a3a24dc5a39252eeaba7c73180d2f9589caf02d9d3e66c6d0a2d0f6335915bcbae8bb60215ca3142a107511b964268ee72635353bd8b8ff827eb82bc050c1ba70e2083cba1658be33d180c4b0ebc6e2235b24abd8059bf443e72a1a1a1081f46fc3e296ee5618790ed1de167309965e0ef31efb79e1c58a1dc3803dc9639f5202525f973481551b18e01156c209da2e464bc8b5b5823dae2f93ff1c2586f11997d050fab82c9e99248abae1266281000a534a1916b6026ea7161a61266492b967e46ed7af20b3e3a1793fd2c7a4b66f4e073b3b6816b9ba259965cb84639cd5e8d0ed405296f3bc316817040463430fb4b6365825051b5aeed4e62c7603c224202190541786f349e72f23e7085c17ac01fbc13bb00b6dd1c2ce892e9115bb9e6cb4690775d455c5afa80c5b33e15bce8a1c494ee82cb51974bdb852d64f1f299fa5bec1bb98258932dc998f0910835e57756ae5af515ea7fb71486c4d72e01d4ee18f670cd415d8784d254d06f54033bb1cb054a503dc810b3824a995ca9d77df60993b0fbd9e019b057c817bedd703b36998e7cbbb0b6d4ecb4bb8c58ac82d9782ab7826627fb016c3dba4d7b70cee15f659428f5eb9415c16206eef40065ef8ba1d93c932fe620cd86367bf65049e0b9dd7c0dd7ee8c0443872bc734287b09e0b5910c3df8c3475a26931330a3f7f3ce518fc5471777248520adad6862090f37973473c1d4c6de0fac951eafda45a1442eadf0cf60b1fec4c00e6d6d281b2bfaccc81dcd47e496fec5ca4ed6307920e2115145cb8d6b242ae542ecf928c097c509a4b62bc06cf6d65f9aa99df6aa7d08260b99aa6cccfc437431f7e0bf5c38bc9a33a2e9c5f4fa3ad25c87e8a7713e283f6bbe830957ec5ea0889c9ac3f13a4353307846b53323101609efcba377b267d68eff3730429d57a07b6e65552fc1fa3dc38fb338f6908fc418df4af474463093d08c51b5f667988edeeb71f61d6f2da31ebd45872f160ad8d35a09e7548276ed4c6feb696d82201d3f1c2545c582a76db512e23020c0f58e3b5cd3afbcbb9ac9f743dd83a18b08e71dbcdf5060fc3ef6dbeb75f033d13e02d1487428173b735666ba8687cc985de444fe2b9b6b7fbe01cf5e9b6483de5021f6bda5394dfe5e12668bad56bb0fbcad71bf50889cacec32225cc2404245c14a2f309e10195d396b71aa8bac789b9c45384e0825684453122fa781d7990269617bd2b42a14c637ce436993bba04c55aab3f4575a9814cb0fd163be7751e5d114ada4a6cafb5f34c3bf130d4e150bd0cc297eed7dd067e20d805db9df860807c12221920c71d5f5f952618e29f1181221b79f66f16399ea44355620bd7c8efd914d21d9c5b9760ae42cefcbddb53ca843a3c6957aca56a884baeaf381f385088397ba57ffe26a43a1161361865636362ee80d0714e39bf1646a3e4b6ac549c0935c272c8e4c73f68287ca7824ae985259"
)
BATCH1_CONCAT = (
    "e2c96409e4691ec247c7524e45fd7da4a09501c165059ff3503794b7e5cbfd45f956b6eddde7a8440b7bdde3b16b001b02cbc97aacaafdec303c31d7996ad02d16e786702cc736c0906ac586012244871c39b30a8769fd88702797d0db283180366f92890f79d2800e222dc5dc0403804a23dc2602d3a260e62ae16da91cdd7ab58d343f5fbeea41061e2c6cdea40403803acb5ae3306b6b49b33fad9aaa97c3a301307b5e3629bcb1018894985e4318fc23ad9a421d3babdacf141b1162b9b8aaac1e9ecdccc84485010f19c4527f184b7ea6eef2f14ea7859a2221e7bdfb1d92703fa2ec74d7a409ea058ffe87e3555ac9f2f7480c4b736513344a882d08dd1ef6de42ddc630f06233ec7dbd679778a9014e7fa6a4e4fd57bc6e9374e538aafc639650cbd968f9f0e1d1f792919f16abe719215e9dbde68b5f1d3091d7f0d37a92e5199b1b1a069768ac05e9bcc34d59cf2a33c7a1f38ce2aa727b1b26766c112684e4431a2029d9ea8e3979c2691942fdee4446522fbe3de3128efe2af93917c489c5fb7431ea1ba8e6a38e668d80610a5347788929426591da6aa9a71227158f4278bc220266c428a32e5e0819a1d51edf9bb2e6a8586620b29b66d2355ea2e56986a2290431e6797ba2bd47cf2191e69ee832d9dafa2303fb09ffa69f696a39f57f4ac46c63baae180354e7ac0e1c1d73ec41af787156597af24ec774891dac47e5872930996c65fd94c0391ea7627d306a900ffcae965b55ad2fbe5f0fab3dddff9ececa1ec5f8174dd962fe1e70d6ab784ec547a653e71b700c93f23d1fa2b8979ea5bc995396faf0583ed512bfdcb0eb63d708257e65c98fbed307181267b71eca8c32c1b6069d5452e3076e908d46f365e1a3fa0e5719cea76d741908439e4f03e6f57261bc856ecd12fd050229d62ac1dd9a16e10a788451b40f7bb68796085b733b83b0c87a74b44d65f3291672980fa252b8b27c3304d05f192dda3dd2fa3755bed8adde7184785adb932b02dad6507ddbe09148124da33dc60047011897a89eadc42114bb70aaa2618bd4eb46f59b6c06163b5a988b9b5ecacc21d758b11b77da956263dc5794a0b900c30f0c21e9d3ecf8503bcff0a54001fe8698a85ba5c72063edd45c3e7ebf093e07cce37b77fb45a4ba847b784ad34259c745a7c9651b8085014ca01d5377edef5922260c5ddded3d2409824fb1b5c964a94eaef3a83d82bfd9fac89328b05eb34d4badb6574cf83eb4395dc344b7fedd020d01a3d400a1e8924a8975931f4a9d63c06563d51380f427dd19c2c9982632248a1a1d463ccb9544101aafc241baf3006d7dbbe629b0ffd4979f1c1604772f43e33f7386cbcbbc6ca9f2dae2ebd5a1ab61329a444bcab3c6aaccd663c6349850bb9daba74765afeb897103552f2230bf6a54fa1342a9709402be059e39cf4f3660de80cc3146051f2692bdce44d1d96753db67fb5f13f659b8f43f298c95573b917e8c76e4cd7ef7e1c3098644095e7ecd92a7a42c931503ac7ea631ad9afa47169a8b08386212ddc024d8c17ef3018f4da4d4a72c29a71471bfee6857fa7f96119de67bdb58a2de0e09556812c37fcb8fc0e45a1a0f12b2ab94c002bd7a61cb2a6d4e260bb25d17bb13078d87cfa71e846dcb0a19c14d28acfada18488f7fd50526d7a89fa4ae165910645a4fb9b0e93dca4fc9faf61e75826e6c9d50ecf6fc693f9fae5578c7e32b736852a3e7e87b9f7bf2c56f139d021081e51803b44877cd9243173d8af4681ecb98796a999760dd2920f376be8239d4c5cf373d508ea6befcae7b892c7a9c73a6e439b6b3521645529017ddf5e15339479a00b63886bdccd878738d2d76142f51434574d37093c44dab5ada342864391b5ac4d2b890f81678737454293570e0a46ba3a0bde2d717248f41e32b0eb3dbcf6920ea0e335ae769e28559e3ff9814b2642cd9ef7eaf4030d7ffa902778b9d7bd99f5edbb5c4fab97dbfa46ea28faf673abe61ab549ccad7ee21dcf20fa9f2c6bcab9f3b1667151b37f2eb037c192529256b957c8920f1bcc2b1778bd0084479c5990e99c67b034a3d4b139d2bf8c7190d6b81db3db8efe15a8620d116012bae05d693461fc4ba66e8822e77ca12f34f98eaad5b669eb5d780784c6ae0c294e7fa5f196276c8d06c2de5f03ea706f49f96e1a6c94277455e374678f8ad66bcae0f56e411e88379a792a6be0a724ee53138beac047c8d378669e0991e57ec17ef43ebc9bbea"
)


def _ts_be_u64(ts: int) -> bytes:
    return int(ts).to_bytes(8, "big", signed=False)


def test_concat_vectors_match_rust_sha256():
    # Tie the pinned 1600-byte messages to the compact digests the Rust KAT
    # pins, so a mistyped concat here is caught before any signature check.
    assert hashlib.sha256(bytes.fromhex(BATCH0_CONCAT)).hexdigest() == BATCH0_CONCAT_SHA256
    assert hashlib.sha256(bytes.fromhex(BATCH1_CONCAT)).hexdigest() == BATCH1_CONCAT_SHA256
    # The slot-0 / slot-1 pks must be the first two 32-byte keys of batch_0.
    assert BATCH0_CONCAT[:64] == SLOT0_PK
    assert BATCH0_CONCAT[64:128] == SIGNER_PK


def test_auth_challenge_sig_verifies_on_relay():
    # 0x01 || nonce(32) || ts_be_u64 — the exact message auth_v2.verify rebuilds.
    message = bytes.fromhex(KAT_NONCE) + _ts_be_u64(KAT_TS)
    assert auth_v2._verify_ed25519_sig(
        SLOT0_PK,
        signature_domain.SIG_DOMAIN_AUTH_CHALLENGE + message,
        AUTH_SIG,
    )
    # Wrong domain (rotation tag) must NOT verify — pins the 0x01/0x02 split,
    # both signed by ephemeral slot keys.
    assert not auth_v2._verify_ed25519_sig(
        SLOT0_PK,
        signature_domain.SIG_DOMAIN_BATCH_ROTATION + message,
        AUTH_SIG,
    )
    # Tamper the timestamp -> must fail (the sig binds nonce AND ts).
    bad_ts = bytes.fromhex(KAT_NONCE) + _ts_be_u64(KAT_TS + 1)
    assert not auth_v2._verify_ed25519_sig(
        SLOT0_PK,
        signature_domain.SIG_DOMAIN_AUTH_CHALLENGE + bad_ts,
        AUTH_SIG,
    )


def test_enrollment_sig_verifies_on_relay():
    # 0x03 || concat(50 batch_0 pk) — signed by the long-term identity key.
    concat = bytes.fromhex(BATCH0_CONCAT)
    assert auth_v2._verify_ed25519_sig(
        LTK_PK,
        signature_domain.SIG_DOMAIN_ENROLLMENT + concat,
        ENROLL_SIG,
    )
    # Enrollment and rotation share the SAME message shape (concat 50 pk); only
    # the domain tag (0x03 vs 0x02) keeps them apart — the exact forgery surface
    # R-C-1 closed. The enroll sig must NOT verify as a rotation.
    assert not auth_v2._verify_ed25519_sig(
        LTK_PK,
        signature_domain.SIG_DOMAIN_BATCH_ROTATION + concat,
        ENROLL_SIG,
    )


def test_rotation_sig_verifies_on_relay():
    # 0x02 || concat(50 batch_1 pk) — signed by the consumed slot (batch_0 #1).
    concat = bytes.fromhex(BATCH1_CONCAT)
    assert auth_v2._verify_ed25519_sig(
        SIGNER_PK,
        signature_domain.SIG_DOMAIN_BATCH_ROTATION + concat,
        ROTATION_SIG,
    )
    # Wrong domain (enrollment tag) must NOT verify.
    assert not auth_v2._verify_ed25519_sig(
        SIGNER_PK,
        signature_domain.SIG_DOMAIN_ENROLLMENT + concat,
        ROTATION_SIG,
    )
    # Wrong signer (the long-term key, not the ephemeral slot) must NOT verify.
    assert not auth_v2._verify_ed25519_sig(
        LTK_PK,
        signature_domain.SIG_DOMAIN_BATCH_ROTATION + concat,
        ROTATION_SIG,
    )
