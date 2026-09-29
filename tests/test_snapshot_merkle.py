"""快照 Merkle 根与单条包含证明测试。

覆盖：
- 根按 seq 升序覆盖 1..watermark 全部字幕与缺口叶子，请求确定、与
  快照创建后的新定稿 / 更正 / 缺口完全无关（旧根不变）；
- 空快照（watermark=0）返回与 snapshot_id 无关的固定空根常量；
- 叶子区分 null 与空文本：空串字幕改叶并改根，缺口文本恒为 null；
- 叶字段完整（快照 ID、seq、kind、revision、原始 / 生效文本、更正版本、
  缺口端点）；奇数层复制末叶（2/3/4/5/6 叶各取代表叶验证）；
- 用独立于 app.merkle 的规范重实现复算叶哈希、根与包含路径，确保
  README 中公布的跨语言字节级序列化可被第三方复现；
- 快照不存在 / seq 越界 -> 404，seq<1 / 非整数 -> 422。
"""

import hashlib

from app import merkle, service
from app.db import read_tx


# ---------- 独立于 app.merkle 的规范重实现（直接按 README 字节规则） ----------

LEAF_PREFIX = b"subtitle-finalizer/merkle:leaf:v1\n"
NODE_PREFIX = b"subtitle-finalizer/merkle:node:v1\n"
EMPTY_PREFIX = b"subtitle-finalizer/merkle:empty:v1\n"

_FIELD_ORDER = (
    "snapshot_id",
    "seq",
    "kind",
    "revision",
    "original_text",
    "effective_text",
    "correction_version",
    "gap_start_seq",
    "gap_end_seq",
)


def _tlv(value) -> bytes:
    if value is None:
        return b"\x03"
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return b"\x01" + len(raw).to_bytes(8, "big") + raw
    return b"\x02" + value.to_bytes(8, "big")


def ref_leaf_hash(entry: dict) -> bytes:
    body = b"".join(_tlv(entry[k]) for k in _FIELD_ORDER)
    return hashlib.sha256(LEAF_PREFIX + body).digest()


def ref_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def ref_root(entries: list) -> bytes:
    if not entries:
        return hashlib.sha256(EMPTY_PREFIX).digest()
    level = [ref_leaf_hash(e) for e in entries]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            ref_node(level[i], level[i + 1]) for i in range(0, len(level), 2)
        ]
    return level[0]


def ref_verify(entry: dict, proof: list, root_hex: str) -> bool:
    cur = ref_leaf_hash(entry)
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        cur = ref_node(sib, cur) if step["side"] == "left" else ref_node(cur, sib)
    return cur.hex() == root_hex


def submit(client, channel, seq, revision=1, text="t"):
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
    resp = client.post(
        f"/channels/{channel}/finalized/{seq}/corrections",
        json={
            "expected_version": expected_version,
            "text": text,
            "reason": reason,
        },
    )
    assert resp.status_code == 200
    return resp.json()


def make_snapshot(client, channel, key):
    resp = client.post(
        f"/channels/{channel}/snapshots", json={"idempotency_key": key}
    )
    assert resp.status_code == 200
    return resp.json()


def merkle_root_of(client, snapshot_id):
    resp = client.get(f"/snapshots/{snapshot_id}/merkle")
    assert resp.status_code == 200
    return resp.json()


def merkle_proof_of(client, snapshot_id, seq):
    resp = client.get(f"/snapshots/{snapshot_id}/merkle", params={"seq": seq})
    assert resp.status_code == 200, resp.text
    return resp.json()


def freeze_entries(snapshot_id):
    """直接读取冻结行，按 v1 叶字段构造独立验证用条目。"""
    with read_tx() as conn:
        rows = conn.execute(
            """
            SELECT seq, kind, revision, original_text, effective_text,
                   correction_version, start_seq, end_seq
            FROM snapshot_items
            WHERE snapshot_id = ? ORDER BY seq
            """,
            (snapshot_id,),
        ).fetchall()
    return [
        {
            "snapshot_id": snapshot_id,
            "seq": r["seq"],
            "kind": r["kind"],
            "revision": r["revision"],
            "original_text": r["original_text"],
            "effective_text": r["effective_text"],
            "correction_version": r["correction_version"],
            "gap_start_seq": r["start_seq"],
            "gap_end_seq": r["end_seq"],
        }
        for r in rows
    ]


# ---------- 空快照固定根 ----------


def test_empty_snapshot_has_fixed_root_constant(client):
    a = make_snapshot(client, "ch-a", "k1")
    b = make_snapshot(client, "ch-b", "k2")
    assert a["watermark"] == 0 and b["watermark"] == 0

    for snap in (a, b):
        body = merkle_root_of(client, snap["snapshot_id"])
        assert body["empty"] is True
        assert body["leaf_count"] == 0
        assert body["merkle_root"] == merkle.EMPTY_ROOT.hex()
        assert body["merkle_root"] == hashlib.sha256(EMPTY_PREFIX).hexdigest()
        assert body["hash_algorithm"] == "sha256"
        assert body["serialization_version"] == "v1"
        assert "seq" in body and body["seq"] is None
        assert body["proof"] is None and body["entry"] is None

    # 与 snapshot_id / 频道无关：两个不同空快照根相同
    assert (
        merkle_root_of(client, a["snapshot_id"])["merkle_root"]
        == merkle_root_of(client, b["snapshot_id"])["merkle_root"]
    )


# ---------- 混合快照：根覆盖全部叶子且跨语言可复算 ----------


def test_root_covers_subtitles_and_gaps_and_is_reproducible(client):
    # 1=字幕（2 个更正）、2-3=缺口、4=字幕（1 更正）、5=字幕（无更正）
    submit(client, "news", 1, 1, "第一条")
    submit(client, "news", 4, 1, "第四条")
    submit(client, "news", 5, 1, "第五条")
    decide_gap(client, "news", 2, 3)
    correct(client, "news", 1, 0, "第一条-改", "r1")
    correct(client, "news", 1, 1, "第一条-再改", "r2")
    correct(client, "news", 4, 0, "第四条-改", "r1")
    snap = make_snapshot(client, "news", "snap-1")

    body = merkle_root_of(client, snap["snapshot_id"])
    assert body["watermark"] == 5
    assert body["leaf_count"] == 5
    assert body["empty"] is False

    entries = freeze_entries(snap["snapshot_id"])
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5]
    assert [e["kind"] for e in entries] == [
        "subtitle",
        "gap",
        "gap",
        "subtitle",
        "subtitle",
    ]
    # 缺口叶子：文本 / revision / 更正版本为 None，端点被冻结
    gap_leaf = entries[1]
    assert gap_leaf["gap_start_seq"] == 2 and gap_leaf["gap_end_seq"] == 3
    assert gap_leaf["revision"] is None
    assert gap_leaf["original_text"] is None
    assert gap_leaf["effective_text"] is None
    assert gap_leaf["correction_version"] is None
    # 字幕叶子：原始与生效文本区分，更正版本冻结在快照时刻
    s1 = entries[0]
    assert s1["original_text"] == "第一条"
    assert s1["effective_text"] == "第一条-再改"
    assert s1["revision"] == 1 and s1["correction_version"] == 2
    assert entries[3]["effective_text"] == "第四条-改"
    assert entries[3]["correction_version"] == 1
    assert entries[4]["correction_version"] == 0

    # 独立重实现复算根（README 字节规范）
    assert body["merkle_root"] == ref_root(entries).hex()


def test_leaf_hash_and_proof_independently_verify(client):
    submit(client, "news", 1, 1, "第一条")
    submit(client, "news", 4, 1, "第四条")
    submit(client, "news", 5, 1, "第五条")
    decide_gap(client, "news", 2, 3)
    snap = make_snapshot(client, "news", "snap-1")
    entries = freeze_entries(snap["snapshot_id"])
    root_hex = merkle_root_of(client, snap["snapshot_id"])["merkle_root"]

    for seq in (1, 2, 3, 4, 5):
        body = merkle_proof_of(client, snap["snapshot_id"], seq)
        entry = entries[seq - 1]

        # 冻结条目回显（自包含 snapshot_id，可直接重算叶哈希）
        payload = body["entry"]
        assert payload["snapshot_id"] == snap["snapshot_id"]
        assert payload["kind"] == entry["kind"]
        assert payload["seq"] == seq
        assert payload["revision"] == entry["revision"]
        assert payload["original_text"] == entry["original_text"]
        assert payload["effective_text"] == entry["effective_text"]
        assert payload["correction_version"] == entry["correction_version"]
        assert payload["start_seq"] == entry["gap_start_seq"]
        assert payload["end_seq"] == entry["gap_end_seq"]

        # 叶哈希由独立实现复算
        assert body["leaf_hash"] == ref_leaf_hash(entry).hex()
        # entry 自包含：仅用响应 payload（重命名端点字段）即可复算同一叶哈希
        from_payload = {
            "snapshot_id": payload["snapshot_id"],
            "seq": payload["seq"],
            "kind": payload["kind"],
            "revision": payload["revision"],
            "original_text": payload["original_text"],
            "effective_text": payload["effective_text"],
            "correction_version": payload["correction_version"],
            "gap_start_seq": payload["start_seq"],
            "gap_end_seq": payload["end_seq"],
        }
        assert ref_leaf_hash(from_payload).hex() == body["leaf_hash"]
        # 路径方向合法、逐层 hex 32 字节
        for step in body["proof"]:
            assert step["side"] in ("left", "right")
            assert len(bytes.fromhex(step["hash"])) == 32
        # 用独立实现按兄弟路径复算到根
        assert ref_verify(entry, body["proof"], root_hex) is True
        # 证明绑定本次快照：换叶即失败（字幕改文本，缺口改端点）
        tampered = dict(entry)
        if entry["kind"] == "gap":
            tampered["gap_end_seq"] = entry["gap_end_seq"] + 1
        else:
            tampered["effective_text"] = entry["effective_text"] + "x"
        assert ref_verify(tampered, body["proof"], root_hex) is False
        # 证明绑定快照 ID
        other_id = dict(entry)
        other_id["snapshot_id"] = "00000000-0000-0000-0000-000000000000"
        assert ref_verify(other_id, body["proof"], root_hex) is False


def test_odd_levels_duplicate_last_leaf_for_various_sizes(client):
    # 构造 1..6 叶各自独立的快照，覆盖奇数层复制末叶与不同树高
    for n in range(1, 7):
        channel = f"ch{n}"
        for seq in range(1, n + 1):
            submit(client, channel, seq, 1, f"字幕-{seq}")
        snap = make_snapshot(client, channel, f"k{n}")
        entries = freeze_entries(snap["snapshot_id"])
        root_body = merkle_root_of(client, snap["snapshot_id"])
        assert root_body["leaf_count"] == n

        body = merkle_proof_of(client, snap["snapshot_id"], n)  # 末叶
        # 独立复算根与包含路径
        assert root_body["merkle_root"] == ref_root(entries).hex()
        assert ref_verify(entries[n - 1], body["proof"],
                          root_body["merkle_root"]) is True

    # 唯一叶：树根即叶哈希，路径为空
    snap1 = make_snapshot(client, "ch1", "k1")
    body = merkle_proof_of(client, snap1["snapshot_id"], 1)
    assert body["proof"] == []
    assert body["leaf_hash"] == body["merkle_root"]

    # 3 叶树（奇数层复制末叶）：末叶的首个兄弟是其自身摘要
    snap3 = make_snapshot(client, "ch3", "k3")
    body3 = merkle_proof_of(client, snap3["snapshot_id"], 3)
    assert body3["proof"][0]["side"] == "right"
    assert body3["proof"][0]["hash"] == body3["leaf_hash"]
    # 叶 2 的首个兄弟在左；叶 1 的首个兄弟在右
    assert merkle_proof_of(client, snap3["snapshot_id"], 2)["proof"][0]["side"] == "left"
    assert merkle_proof_of(client, snap3["snapshot_id"], 1)["proof"][0]["side"] == "right"
    # 路径长度逐层：3 叶 -> 2 层
    assert len(body3["proof"]) == 2
    # 2 叶 / 4 叶只有 1 层 / 2 层
    snap2 = make_snapshot(client, "ch2", "k2")
    assert len(merkle_proof_of(client, snap2["snapshot_id"], 1)["proof"]) == 1
    snap4 = make_snapshot(client, "ch4", "k4")
    assert len(merkle_proof_of(client, snap4["snapshot_id"], 1)["proof"]) == 2


def test_null_distinct_from_empty_text_changes_root(client):
    # 同形结构（1 条字幕），一条文本为空串、另一条非空：叶与根必须不同
    submit(client, "c-empty", 1, 7, "")
    submit(client, "c-full", 1, 7, "x")
    snap_empty = make_snapshot(client, "c-empty", "k")
    snap_full = make_snapshot(client, "c-full", "k")

    e_empty = freeze_entries(snap_empty["snapshot_id"])[0]
    e_full = freeze_entries(snap_full["snapshot_id"])[0]
    assert e_empty["original_text"] == "" and e_empty["effective_text"] == ""
    assert e_full["original_text"] == "x"

    p_empty = merkle_proof_of(client, snap_empty["snapshot_id"], 1)
    p_full = merkle_proof_of(client, snap_full["snapshot_id"], 1)
    assert p_empty["leaf_hash"] == ref_leaf_hash(e_empty).hex()
    assert p_full["leaf_hash"] == ref_leaf_hash(e_full).hex()
    assert p_empty["leaf_hash"] != p_full["leaf_hash"]
    assert p_empty["merkle_root"] != p_full["merkle_root"]
    # 空串不是 null：独立实现显式比对 TLV 首字节
    assert merkle.encode_leaf(e_empty) != merkle.encode_leaf({
        **e_empty, "original_text": None, "effective_text": None,
    })


def test_root_is_deterministic_and_frozen_after_later_writes(client):
    submit(client, "news", 1, 1, "第一条")
    decide_gap(client, "news", 2, 3)
    snap = make_snapshot(client, "news", "snap-1")

    first = merkle_root_of(client, snap["snapshot_id"])
    p1 = merkle_proof_of(client, snap["snapshot_id"], 1)

    # 相同请求结果确定（重复调用字节一致）
    assert merkle_root_of(client, snap["snapshot_id"]) == first
    assert merkle_proof_of(client, snap["snapshot_id"], 1) == p1

    # 快照之后：新定稿、新更正、新缺口都不得改变旧快照根
    correct(client, "news", 1, 0, "第一条-快照后更正", "late")
    submit(client, "news", 4, 1, "第四条")
    submit(client, "news", 5, 1, "第五条")
    assert merkle_root_of(client, snap["snapshot_id"])["merkle_root"] == first["merkle_root"]
    later_p1 = merkle_proof_of(client, snap["snapshot_id"], 1)
    assert later_p1["leaf_hash"] == p1["leaf_hash"]
    assert later_p1["entry"]["effective_text"] == "第一条"
    assert later_p1["entry"]["correction_version"] == 0

    # 新快照（包含后续状态）根不同，且与旧快照可独立验证
    snap2 = make_snapshot(client, "news", "snap-2")
    second = merkle_root_of(client, snap2["snapshot_id"])
    assert second["merkle_root"] != first["merkle_root"]
    entries2 = freeze_entries(snap2["snapshot_id"])
    assert second["merkle_root"] == ref_root(entries2).hex()


def test_snapshot_with_correction_freeze_at_creation_time(client):
    # 更正发生在快照之前 -> 叶子冻结生效文本与版本；快照后的更正不入叶
    submit(client, "news", 1, 1, "原文")
    correct(client, "news", 1, 0, "改1", "r")
    snap = make_snapshot(client, "news", "k")
    body = merkle_proof_of(client, snap["snapshot_id"], 1)
    assert body["entry"]["original_text"] == "原文"
    assert body["entry"]["effective_text"] == "改1"
    assert body["entry"]["correction_version"] == 1
    correct(client, "news", 1, 1, "改2", "r2")
    body2 = merkle_proof_of(client, snap["snapshot_id"], 1)
    assert body2["entry"]["effective_text"] == "改1"
    assert body2["entry"]["correction_version"] == 1
    assert body2["leaf_hash"] == body["leaf_hash"]


# ---------- 服务层直调（422 兜底）与 HTTP 错误码 ----------


def test_snapshot_not_found_404(client):
    resp = client.get("/snapshots/does-not-exist/merkle")
    assert resp.status_code == 404
    assert resp.json()["error"] == "snapshot_not_found"

    # seq 校验在快照存在性之后 / 或不存在快照时：仍按不存在快照 404
    resp = client.get(
        "/snapshots/does-not-exist/merkle", params={"seq": 1}
    )
    assert resp.status_code == 404
    assert resp.json()["error"] == "snapshot_not_found"


def test_seq_out_of_watermark_404(client):
    snap = make_snapshot(client, "news", "k-empty")
    # 空快照：任何 seq>=1 都越界
    resp = client.get(
        f"/snapshots/{snap['snapshot_id']}/merkle", params={"seq": 1}
    )
    assert resp.status_code == 404
    assert resp.json()["error"] == "seq_out_of_snapshot"

    submit(client, "news", 1, 1, "第一条")
    snap2 = make_snapshot(client, "news", "k2")
    resp = client.get(
        f"/snapshots/{snap2['snapshot_id']}/merkle", params={"seq": 2}
    )
    assert resp.status_code == 404
    assert resp.json()["error"] == "seq_out_of_snapshot"


def test_invalid_seq_422(client):
    snap = make_snapshot(client, "news", "k")
    # seq=0 / 负数 / 非整数 -> 422
    for bad in ("0", "-1", "abc"):
        resp = client.get(
            f"/snapshots/{snap['snapshot_id']}/merkle", params={"seq": bad}
        )
        assert resp.status_code == 422, bad

    # 服务层直调同样兜底为 422 invalid_seq
    try:
        service.get_snapshot_merkle(snap["snapshot_id"], seq=0)
        assert False, "应当抛出 SnapshotError"
    except service.SnapshotError as exc:
        assert exc.status_code == 422
        assert exc.error == "invalid_seq"
