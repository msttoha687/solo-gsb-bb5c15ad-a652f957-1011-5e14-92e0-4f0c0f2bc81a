"""快照 Merkle 封存验真测试。

覆盖：
- 根按 1..watermark 覆盖全部字幕与缺口；空快照固定根；单叶树根即叶摘要；
- 奇数层复制末叶（n=3/5/6 等），包含证明带左右方向与 duplicated 标记；
- 叶负载固定 9 键、UTF-8 规范序列化（仅转义必需字符），与 json 紧凑模式一致；
- 缺口叶 null 与字幕空文本 "" 严格区分；revision/original/effective/
  correction_version/缺口端点全部进叶负载；
- 叶子 / 内部不同域前缀，篡改任一兄弟必验签失败；
- 只读冻结：快照后新定稿 / 新更正 / 新缺口不改变旧快照根；重复请求确定；
- 404（快照不存在 / seq 越界 / 空快照带 seq）与 422（seq<1 / 非整数）。

所有断言均用仅依赖标准库的**独立参考实现**复算（不调用 app.merkle），
确保规范本身可跨语言重放。
"""

import hashlib
import json

from app import merkle as app_merkle
from app.db import write_tx


# ---------- 独立参考实现（仅标准库，镜像 README 中的跨语言规范） ----------

SCHEME = "snapshot-merkle:v1"
LEAF_PREFIX = b"snapshot-merkle:v1:leaf:"
NODE_PREFIX = b"snapshot-merkle:v1:node:"
EMPTY_ROOT = hashlib.sha256(b"snapshot-merkle:v1:empty").hexdigest()


def ref_canonical(value) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def ref_leaf_hash(entry: dict) -> str:
    return hashlib.sha256(LEAF_PREFIX + ref_canonical(entry)).hexdigest()


def ref_node_hash(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(
        NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def ref_root(entries: list) -> str:
    if not entries:
        return EMPTY_ROOT
    level = [ref_leaf_hash(e) for e in entries]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(ref_node_hash(left, right))
        level = nxt
    return level[0]


def ref_verify(entry: dict, index: int, leaf_count: int, path: list, root: str) -> bool:
    """方向 / 复制位全部由 (index, leaf_count) 推导，不信任路径自报值。"""
    if leaf_count < 1 or not 0 <= index < leaf_count:
        return False
    cur = ref_leaf_hash(entry)
    level_len, idx = leaf_count, index
    for step in path:
        if level_len == 1:
            return False  # 已到根，路径不应再给出兄弟
        if set(step) != {"level", "side", "hash", "duplicated"}:
            return False
        expect_dup = idx % 2 == 0 and idx + 1 >= level_len
        if step["duplicated"] != expect_dup:
            return False
        sib = step["hash"]
        if idx % 2 == 0:
            if step["side"] != "right":
                return False
            if expect_dup and sib != cur:
                return False
            cur = ref_node_hash(cur, cur if expect_dup else sib)
        else:
            if step["side"] != "left":
                return False
            cur = ref_node_hash(sib, cur)
        level_len = (level_len + 1) // 2
        idx //= 2
    return level_len == 1 and idx == 0 and cur == root


# ---------- 造数辅助 ----------


def submit(client, channel, seq, revision, text="t"):
    resp = client.post(
        f"/channels/{channel}/fragments",
        json={"seq": seq, "revision": revision, "text": text},
    )
    assert resp.status_code == 200
    return resp.json()


def decide_gap(client, channel, start_seq, end_seq):
    return client.post(
        f"/channels/{channel}/gaps",
        json={"start_seq": start_seq, "end_seq": end_seq},
    )


def correct(client, channel, seq, expected_version, text, reason):
    return client.post(
        f"/channels/{channel}/finalized/{seq}/corrections",
        json={
            "expected_version": expected_version,
            "text": text,
            "reason": reason,
        },
    )


def make_snapshot(client, channel, key):
    resp = client.post(
        f"/channels/{channel}/snapshots", json={"idempotency_key": key}
    )
    assert resp.status_code == 200
    return resp.json()


def ref_entries_from_snapshot(client, sid):
    """通过已发布的 items 接口独立重建叶负载（原始 + 生效两视图合并）。"""
    effective = client.get(
        f"/snapshots/{sid}/items", params={"view": "effective"}
    ).json()["items"]
    original = client.get(f"/snapshots/{sid}/items").json()["items"]
    original_by_seq = {i["seq"]: i for i in original}
    entries = []
    for it in effective:
        if it["kind"] == "gap":
            entries.append(
                {
                    "snapshot_id": sid,
                    "seq": it["seq"],
                    "kind": "gap",
                    "revision": None,
                    "original_text": None,
                    "effective_text": None,
                    "correction_version": None,
                    "gap_start": it["start_seq"],
                    "gap_end": it["end_seq"],
                }
            )
        else:
            entries.append(
                {
                    "snapshot_id": sid,
                    "seq": it["seq"],
                    "kind": "subtitle",
                    "revision": it["revision"],
                    "original_text": original_by_seq[it["seq"]]["text"],
                    "effective_text": it["text"],
                    "correction_version": it["correction_version"],
                    "gap_start": None,
                    "gap_end": None,
                }
            )
    return entries


def build_mixed(client, channel="news"):
    """1=字幕(2 更正)、2-3=缺口、4=字幕(1 更正,rev=2)、5=字幕(无更正)。"""
    submit(client, channel, 1, 1, "第一条")
    submit(client, channel, 4, 2, "第四条")
    submit(client, channel, 5, 1, "第五条")
    decide_gap(client, channel, 2, 3)
    correct(client, channel, 1, 0, "第一条-改", "r1")
    correct(client, channel, 1, 1, "第一条-再改", "r2")
    correct(client, channel, 4, 0, "第四条-改", "r1")
    return make_snapshot(client, channel, "snap-1")


def merkle_root(client, sid, params=None):
    return client.get(f"/snapshots/{sid}/merkle", params=params or {})


# ---------- 根：空快照固定根 / 覆盖字幕与缺口 / 独立复算 ----------


def test_empty_snapshot_has_fixed_root(client):
    snap = make_snapshot(client, "ghost", "empty-1")
    body = merkle_root(client, snap["snapshot_id"]).json()
    assert body["mode"] == "root"
    assert body["scheme"] == SCHEME
    assert body["hash_algorithm"] == "SHA-256"
    assert body["hash_encoding"] == "hex"
    assert body["watermark"] == 0
    assert body["leaf_count"] == 0
    assert body["empty"] is True
    assert body["root"] == EMPTY_ROOT
    assert (
        body["root"]
        == "b86d2a826337412bf3e880be522659e83d4638b1ccb5b4d0d71d59af5ac31575"
    )
    # 所有空快照共享固定根
    other = make_snapshot(client, "ghost2", "empty-2")
    assert merkle_root(client, other["snapshot_id"]).json()["root"] == EMPTY_ROOT


def test_root_covers_all_subtitles_and_gaps_and_is_independently_recomputable(client):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    body = merkle_root(client, sid).json()
    assert body["leaf_count"] == 5
    assert body["empty"] is False
    entries = ref_entries_from_snapshot(client, sid)
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5]
    assert [e["kind"] for e in entries] == [
        "subtitle",
        "gap",
        "gap",
        "subtitle",
        "subtitle",
    ]
    assert body["root"] == ref_root(entries)
    # 固定 9 键、固定键序
    assert all(list(e.keys()) == list(app_merkle.LEAF_KEYS) for e in entries)


def test_root_is_read_only_and_deterministic(client):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    first = merkle_root(client, sid).json()
    second = merkle_root(client, sid).json()
    assert first == second


def test_root_depends_on_every_frozen_field(client):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    entries = ref_entries_from_snapshot(client, sid)
    root = ref_root(entries)

    # 逐字段篡改都应改变根（在 seq1 字幕叶上）
    e = dict(entries[0])
    for field, value in (
        ("snapshot_id", sid + "x"),
        ("seq", 42),
        ("kind", "gap"),
        ("revision", 99),
        ("original_text", "篡改"),
        ("effective_text", "篡改"),
        ("correction_version", 9),
        ("gap_start", 1),
        ("gap_end", 2),
    ):
        changed = list(entries)
        modified = dict(e)
        modified[field] = value
        changed[0] = modified
        assert ref_root(changed) != root, field


# ---------- 单叶树与奇数层复制末叶 ----------


def test_single_leaf_root_is_leaf_hash_with_empty_path(client):
    submit(client, "one", 1, 3, "solo")
    snap = make_snapshot(client, "one", "k")
    body = merkle_root(client, snap["snapshot_id"]).json()
    proof = merkle_root(
        client, snap["snapshot_id"], params={"seq": 1}
    ).json()
    entry = {
        "snapshot_id": snap["snapshot_id"],
        "seq": 1,
        "kind": "subtitle",
        "revision": 3,
        "original_text": "solo",
        "effective_text": "solo",
        "correction_version": 0,
        "gap_start": None,
        "gap_end": None,
    }
    assert proof["proof"]["path"] == []
    assert proof["leaf_hash"] == ref_leaf_hash(entry)
    assert body["root"] == proof["leaf_hash"]


def test_odd_levels_duplicate_last_leaf_for_leaf_counts_1_to_8(client):
    """n=2/3/5/6/7 等规模逐层验证复制位；n=3 时根 = H(H(1,2), H(3,3))。"""
    for n in range(1, 9):
        channel = f"ch{n}"
        for s in range(1, n + 1):
            submit(client, channel, s, 0, f"text-{s}")
        snap = make_snapshot(client, channel, "k")
        sid = snap["snapshot_id"]
        body = merkle_root(client, sid).json()
        entries = ref_entries_from_snapshot(client, sid)
        assert body["root"] == ref_root(entries)

        # 最后一个叶子：n 为奇数 >1 时第一层兄弟必须是复制（hash 相同）
        last = merkle_root(client, sid, params={"seq": n}).json()
        step0 = last["proof"]["path"][0] if n > 1 else None
        if n > 1 and n % 2 == 1:
            assert step0["side"] == "right"
            assert step0["duplicated"] is True
            assert step0["hash"] == last["leaf_hash"]
        elif n > 1:
            assert step0["duplicated"] is False

        # 每条证明独立复算到根
        for seq in range(1, n + 1):
            p = merkle_root(client, sid, params={"seq": seq}).json()
            assert ref_verify(
                p["leaf"],
                p["leaf_index"],
                n,
                p["proof"]["path"],
                body["root"],
            )


def test_three_leaf_root_has_known_duplicated_structure(client):
    """显式验证 n=3：叶子层 [1,2,3] -> [H12, H33] -> 根。"""
    for s in (1, 2, 3):
        submit(client, "c3", s, 1, f"t{s}")
    snap = make_snapshot(client, "c3", "k")
    sid = snap["snapshot_id"]
    entries = ref_entries_from_snapshot(client, sid)
    h1, h2, h3 = (ref_leaf_hash(e) for e in entries)
    expected = ref_node_hash(ref_node_hash(h1, h2), ref_node_hash(h3, h3))
    body = merkle_root(client, sid).json()
    assert body["root"] == expected

    p3 = merkle_root(client, sid, params={"seq": 3}).json()
    assert p3["proof"]["path"] == [
        {"level": 0, "side": "right", "hash": h3, "duplicated": True},
        {
            "level": 1,
            "side": "left",
            "hash": ref_node_hash(h1, h2),
            "duplicated": False,
        },
    ]
    p2 = merkle_root(client, sid, params={"seq": 2}).json()
    assert p2["proof"]["path"][0] == {
        "level": 0,
        "side": "left",
        "hash": h1,
        "duplicated": False,
    }
    assert p2["proof"]["path"][1]["side"] == "right"
    assert p2["proof"]["path"][1]["duplicated"] is False


# ---------- 指定 seq：冻结条目 / 叶哈希 / 带方向兄弟路径 ----------


def test_seq_proof_returns_frozen_entry_leaf_hash_and_directional_path(client):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    body = merkle_root(client, sid).json()

    for seq in (1, 2, 3, 4, 5):
        p = merkle_root(client, sid, params={"seq": seq}).json()
        assert p["mode"] == "proof"
        assert p["seq"] == seq
        assert p["leaf_index"] == seq - 1
        assert p["proof"]["root"] == body["root"]
        assert p["leaf_hash"] == ref_leaf_hash(p["leaf"])
        # 每条路径都能严格复算到根（方向 / 复制位由 index 独立推导）
        assert ref_verify(
            p["leaf"],
            p["leaf_index"],
            body["leaf_count"],
            p["proof"]["path"],
            body["root"],
        )

    # 显式检查 seq1（字幕、有 2 个更正）冻结内容
    p1 = merkle_root(client, sid, params={"seq": 1}).json()["leaf"]
    assert p1 == {
        "snapshot_id": sid,
        "seq": 1,
        "kind": "subtitle",
        "revision": 1,
        "original_text": "第一条",
        "effective_text": "第一条-再改",
        "correction_version": 2,
        "gap_start": None,
        "gap_end": None,
    }

    # 缺口叶：字幕字段全 null，缺口端点冻结
    p2 = merkle_root(client, sid, params={"seq": 2}).json()["leaf"]
    assert p2["kind"] == "gap"
    assert p2["revision"] is None
    assert p2["original_text"] is None
    assert p2["effective_text"] is None
    assert p2["correction_version"] is None
    assert (p2["gap_start"], p2["gap_end"]) == (2, 3)

    # seq5（无更正）correction_version=0
    p5 = merkle_root(client, sid, params={"seq": 5}).json()["leaf"]
    assert p5["correction_version"] == 0
    assert p5["revision"] == 1


def test_null_gap_fields_distinguished_from_empty_text(client):
    submit(client, "mix", 1, 1, "")  # 空文本字幕（"" 而非 null）
    decide_gap(client, "mix", 2, 2)  # 缺口
    snap = make_snapshot(client, "mix", "k")
    sid = snap["snapshot_id"]
    p1 = merkle_root(client, sid, params={"seq": 1}).json()
    p2 = merkle_root(client, sid, params={"seq": 2}).json()

    assert p1["leaf"]["original_text"] == ""
    assert p1["leaf"]["effective_text"] == ""
    assert p1["leaf"]["gap_start"] is None
    assert p2["leaf"]["original_text"] is None
    assert p2["leaf"]["effective_text"] is None
    assert p2["leaf"]["gap_start"] == 2

    # 规范负载中 "" 与 null 文本不同，叶哈希不同，方向路径同样可验
    assert '"original_text":""' in p1["leaf_canonical_payload"]
    assert '"original_text":null' in p2["leaf_canonical_payload"]
    assert p1["leaf_hash"] != p2["leaf_hash"]
    body = merkle_root(client, sid).json()
    for p in (p1, p2):
        assert ref_verify(
            p["leaf"],
            p["leaf_index"],
            2,
            p["proof"]["path"],
            body["root"],
        )


def test_leaf_canonical_payload_is_utf8_and_escapes_only_required_chars(client):
    # 引号 / 反斜杠 / 换行必须转义；中文 / emoji / U+007F / U+2028 / U+2029 原样
    text = (
        '中文😀"\n\t\x01\x7f\u2028\u2029'
    )
    submit(client, "u", 1, 1, text)
    snap = make_snapshot(client, "u", "k")
    p = merkle_root(client, snap["snapshot_id"], params={"seq": 1}).json()
    payload = p["leaf_canonical_payload"]
    assert payload.encode("utf-8") == ref_canonical(p["leaf"])
    assert '\\"' in payload and "\\n" in payload and "\\t" in payload
    assert "\\u0001" in payload
    assert "中文" in payload and "😀" in payload
    assert "\x7f" in payload and "\u2028" in payload and "\u2029" in payload
    assert "\\u007f" not in payload  # DEL(U+007F) 不转义
    assert "\\u2028" not in payload and "\\u2029" not in payload  # 非 ASCII 不转义
    assert "<html" not in payload  # 本串无 HTML 字符，顺带说明不做 HTML 转义


def test_canonical_serializer_matches_json_compact_for_diverse_payloads():
    """app 自有规范序列化器与 json 紧凑模式在各种负载上字节一致。"""
    payloads = [
        None,
        True,
        False,
        0,
        -17,
        123456789,
        "",
        "plain ascii",
        'q"\\b\f\n\r\t\x00\x1f\x7f中文😀\u2028\u2029',
        [],
        [1, "两", None, [True, False], {}],
        {"z": 1, "a": "中", "n": None, "e": {"x": []}},
    ]
    for value in payloads:
        got = app_merkle.canonical_dumps(value)
        assert got == ref_canonical(value), value


# ---------- 域分离与防篡改 ----------


def test_leaf_and_node_domain_prefixes_are_distinct():
    digest = hashlib.sha256(b"x").hexdigest()
    leaf = hashlib.sha256(LEAF_PREFIX + b"x").hexdigest()
    node = ref_node_hash(digest, digest)
    assert leaf != digest and node != digest and leaf != node
    assert app_merkle.hash_node(digest, digest) == node
    # 空快照根不等于任何空输入的裸哈希
    assert EMPTY_ROOT != hashlib.sha256(b"").hexdigest()


def test_tampered_proof_fails_verification(client):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    root = merkle_root(client, sid).json()["root"]
    p = merkle_root(client, sid, params={"seq": 1}).json()
    path = p["proof"]["path"]

    # 篡改任一兄弟哈希 -> 失败
    bad = [dict(step) for step in path]
    flipped = "".join("0" if c == "f" else "f" for c in bad[0]["hash"][:2])
    bad[0]["hash"] = flipped + bad[0]["hash"][2:]
    assert not ref_verify(p["leaf"], 0, 5, bad, root)

    # 伪造方向 -> 失败
    bad = [dict(step) for step in path]
    bad[0]["side"] = "left"
    assert not ref_verify(p["leaf"], 0, 5, bad, root)

    # 伪造复制位 -> 失败
    bad = [dict(step) for step in path]
    bad[0]["duplicated"] = not bad[0]["duplicated"]
    assert not ref_verify(p["leaf"], 0, 5, bad, root)

    # 篡改叶子条目（effective_text）-> 失败
    tampered_entry = dict(p["leaf"])
    tampered_entry["effective_text"] = "伪造"
    assert not ref_verify(tampered_entry, 0, 5, path, root)

    # 错误的根 / 错误的 index / 路径与声称叶子数不符 -> 失败
    assert not ref_verify(p["leaf"], 0, 5, path, "0" * 64)
    assert not ref_verify(p["leaf"], 1, 5, path, root)
    assert not ref_verify(p["leaf"], 0, 4, path, root)
    # 路径过短（少一步，最终不在根层）-> 失败
    assert not ref_verify(p["leaf"], 0, 5, path[:-1], root)

    # 未被篡改的原证明通过
    assert ref_verify(p["leaf"], 0, 5, path, root)


def test_builtin_strict_verifier_agrees_with_reference(client):
    """app.merkle.verify_inclusion_proof 与独立参考实现结论一致。"""
    for n in range(1, 8):
        channel = f"vc{n}"
        for s in range(1, n + 1):
            submit(client, channel, s, 0, f"x{s}")
        snap = make_snapshot(client, channel, "k")
        sid = snap["snapshot_id"]
        root = merkle_root(client, sid).json()["root"]
        for seq in range(1, n + 1):
            p = merkle_root(client, sid, params={"seq": seq}).json()
            ok = app_merkle.verify_inclusion_proof(
                leaf_hash=p["leaf_hash"],
                index=p["leaf_index"],
                leaf_count=n,
                path=p["proof"]["path"],
                root_hex=root,
            )
            assert ok is True
            # 喂错根即失败
            bad = app_merkle.verify_inclusion_proof(
                leaf_hash=p["leaf_hash"],
                index=p["leaf_index"],
                leaf_count=n,
                path=p["proof"]["path"],
                root_hex="0" * 64,
            )
            assert bad is False


# ---------- 冻结性：快照后变化不改变旧根 ----------


def test_later_finalizations_corrections_and_gaps_do_not_change_old_root(client):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    before = merkle_root(client, sid).json()
    before_seq1 = merkle_root(client, sid, params={"seq": 1}).json()

    # 快照后：旧序号再更正、新片段、新缺口、频道水位推进
    correct(client, "news", 1, 2, "第一条-快照后再改", "r3")
    correct(client, "news", 5, 0, "第五条-改", "r1")
    submit(client, "news", 8, 1, "第八条")
    decide_gap(client, "news", 6, 7)

    after = merkle_root(client, sid).json()
    after_seq1 = merkle_root(client, sid, params={"seq": 1}).json()
    assert after == before
    assert after_seq1 == before_seq1
    assert after["root"] == before["root"]
    # 新快照（水位线 8）根应不同
    snap2 = make_snapshot(client, "news", "snap-2")
    after2 = merkle_root(client, snap2["snapshot_id"]).json()
    assert after2["leaf_count"] == 8
    assert after2["root"] != before["root"]


def test_different_snapshot_ids_with_identical_content_have_different_roots(client):
    """snapshot_id 进叶负载：即使冻结内容一致，不同快照的根也不同（绑定快照）。"""
    submit(client, "a", 1, 1, "same")
    submit(client, "b", 1, 1, "same")
    sa = make_snapshot(client, "a", "ka")
    sb = make_snapshot(client, "b", "kb")
    ra = merkle_root(client, sa["snapshot_id"]).json()["root"]
    rb = merkle_root(client, sb["snapshot_id"]).json()["root"]
    assert ra != rb


# ---------- 错误路径 ----------


def test_merkle_unknown_snapshot_returns_404(client):
    resp = merkle_root(client, "no-such-snapshot")
    assert resp.status_code == 404
    assert resp.json()["error"] == "snapshot_not_found"


def test_merkle_seq_out_of_range_returns_404(client):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    resp = merkle_root(client, sid, params={"seq": 6})
    assert resp.status_code == 404
    assert resp.json()["error"] == "seq_out_of_snapshot"

    # 空快照的任意 seq 都是越界
    empty = make_snapshot(client, "ghost", "e")
    resp = merkle_root(client, empty["snapshot_id"], params={"seq": 1})
    assert resp.status_code == 404
    assert resp.json()["error"] == "seq_out_of_snapshot"

    # 未知快照优先 404 snapshot_not_found
    assert merkle_root(client, "nope", params={"seq": 1}).status_code == 404


def test_merkle_invalid_seq_returns_422(client):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    assert merkle_root(client, sid, params={"seq": 0}).status_code == 422
    assert client.get(f"/snapshots/{sid}/merkle?seq=-3").status_code == 422
    assert client.get(f"/snapshots/{sid}/merkle?seq=abc").status_code == 422
    assert client.get(f"/snapshots/{sid}/merkle?seq=1.5").status_code == 422


# ---------- 只读：不写入、存储层冻结 ----------


def test_merkle_is_read_only_against_storage(client, conn):
    snap = build_mixed(client)
    sid = snap["snapshot_id"]
    merkle_root(client, sid)
    for seq in range(1, 6):
        merkle_root(client, sid, params={"seq": seq})

    # 接口期间不新增任何快照行；不可变触发器仍拦截直接改写
    assert conn.execute(
        "SELECT COUNT(*) AS c FROM snapshots"
    ).fetchone()["c"] == 1
    import sqlite3

    import pytest

    with pytest.raises(sqlite3.DatabaseError):
        with write_tx() as c:
            c.execute(
                "UPDATE snapshot_items SET effective_text='x' "
                "WHERE snapshot_id=? AND seq=1",
                (sid,),
            )
