"""发布快照的 SHA-256 Merkle 根与单条包含证明（跨语言可复算规范 v1）。

下游导出字幕时需要证明“单条内容确属某次发布快照”：本模块只对快照冻结
数据做纯函数计算（不读库、不写库），给出：

- 覆盖快照 1..watermark 全部叶子（字幕与缺口一视同仁、各占一叶）的
  Merkle 根，空快照有与 snapshot_id 无关的固定根 EMPTY_ROOT；
- 指定某叶时给出从叶到根、逐层带左右方向的兄弟路径，供离线验真。

完整字节级规范同时写在 README「快照 Merkle 验真」一节。任何语言按下述
规则实现都能独立复算出完全一致的十六进制摘要。

约定
----
- 哈希算法：SHA-256，摘要为 32 字节；JSON 输出一律小写十六进制；
- 整数：大端（network byte order），8 字节无符号 uint64；
- 字符串：原始 Unicode 码点的 UTF-8 字节，不做任何归一化，不加结尾符；
- null 与空字符串是两种不同的值（标签不同），叶子据此区分“缺口没有
  文本（null）”与“定稿文本就是空串 ""”。

字段值编码（TLV，单字节 tag，长度仅字符串携带）
---------------------------------------------
- 字符串：tag=0x01 ‖ uint64(UTF-8 字节数) ‖ UTF-8 字节；
- 整数：  tag=0x02 ‖ uint64 BE（固定 8 字节载荷）；
- null：  tag=0x03（零载荷）。

叶记录（9 个字段，固定顺序，不写字段名，逐字段 TLV 拼接）
-------------------------------------------------------
snapshot_id, seq, kind, revision, original_text, effective_text,
correction_version, gap_start_seq, gap_end_seq

叶哈希 = SHA256(LEAF_PREFIX ‖ 叶记录)。kind 为 "subtitle" | "gap"：
字幕行 revision/文本/correction_version 有值、缺口端点为 null；缺口行
反之（文本字段为 null 而非 ""）。

内部节点 = SHA256(NODE_PREFIX ‖ 左孩子摘要 ‖ 右孩子摘要)（各 32 字节）。

建树 / 包含证明
--------------
- 叶子严格按 seq 升序（1..watermark 每个序号恰好一叶）；
- 逐层两两配对；某层节点数为大于 1 的奇数时，把末节点复制一份再配对，
  因此“被复制”的兄弟会真实出现在包含路径中（其摘要等于当前节点摘要）；
- 一层仅剩 1 个节点时它就是根；唯一叶的树根就是该叶哈希本身；
- 路径方向 side 表示**兄弟相对当前节点**的位置：
  side="left" 表示兄弟是左孩子，复算时 node(sibling, current)；
  side="right" 表示兄弟是右孩子，复算时 node(current, sibling)。

三个 ASCII 域分离前缀均以换行符（0x0A）结尾，叶 / 内部 / 空根互不共用：
"""

import hashlib

SERIALIZATION_VERSION = "v1"
HASH_ALGORITHM = "sha256"

LEAF_PREFIX = b"subtitle-finalizer/merkle:leaf:v1\n"
NODE_PREFIX = b"subtitle-finalizer/merkle:node:v1\n"
EMPTY_PREFIX = b"subtitle-finalizer/merkle:empty:v1\n"

_TAG_STRING = b"\x01"
_TAG_UINT = b"\x02"
_TAG_NULL = b"\x03"
_UINT_BYTES = 8

# 空快照（watermark=0，零叶）的固定根：仅由 EMPTY_PREFIX 决定，与快照 ID
# / 频道 / 创建时刻均无关，所有空快照共享此值。
EMPTY_ROOT = hashlib.sha256(EMPTY_PREFIX).digest()

# 叶记录字段的固定顺序；跨语言实现必须严格使用同一顺序。
LEAF_FIELDS = (
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


def _encode_uint(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Merkle 字段整数超出 uint64 范围")
    return _TAG_UINT + value.to_bytes(_UINT_BYTES, "big")


def _encode_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("字符串 UTF-8 字节数超出 uint64 范围")
    return _TAG_STRING + len(raw).to_bytes(_UINT_BYTES, "big") + raw


def _encode_field(value) -> bytes:
    if value is None:
        return _TAG_NULL
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return _encode_uint(value)
    raise TypeError(f"不支持的叶字段类型：{type(value)!r}")


def encode_leaf(entry: dict) -> bytes:
    """按 v1 规范序列化一个叶条目（9 字段定序 TLV 拼接）。"""
    try:
        return b"".join(_encode_field(entry[name]) for name in LEAF_FIELDS)
    except KeyError as exc:
        raise ValueError(f"叶条目缺少字段：{exc.args[0]}") from None


def leaf_hash(entry: dict) -> bytes:
    """叶摘要 = SHA256(LEAF_PREFIX ‖ 规范序列化叶记录)。"""
    return hashlib.sha256(LEAF_PREFIX + encode_leaf(entry)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """内部节点摘要 = SHA256(NODE_PREFIX ‖ 左 32B ‖ 右 32B)。"""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _pair_up(level: list) -> list:
    """一层两两配对；节点数为大于 1 的奇数时复制末节点。"""
    if len(level) > 1 and len(level) % 2 == 1:
        level = [*level, level[-1]]
    return [
        node_hash(level[i], level[i + 1])
        for i in range(0, len(level), 2)
    ]


def merkle_root(leaves: list) -> bytes:
    """由叶摘要（按 seq 升序）求根；零叶返回固定 EMPTY_ROOT。"""
    if not leaves:
        return EMPTY_ROOT
    level = list(leaves)
    while len(level) > 1:
        level = _pair_up(level)
    return level[0]


def inclusion_proof(leaves: list, index: int):
    """求 leaves[index] 的包含路径。

    返回 [(side, sibling_digest), ...]，自叶层向上、终于根的直接孩子；
    side 为兄弟相对当前节点的位置（"left"/"right"）。奇数层复制末叶时，
    被复制出的兄弟就是当前节点自身的摘要，验证方无需任何特殊处理。
    """
    if not 0 <= index < len(leaves):
        raise IndexError("叶下标越界")
    path = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = [*level, level[-1]]
        if idx % 2 == 0:
            # 当前节点是左孩子，兄弟在右
            path.append(("right", level[idx + 1]))
        else:
            # 当前节点是右孩子，兄弟在左
            path.append(("left", level[idx - 1]))
        idx //= 2
        level = [
            node_hash(level[i], level[i + 1])
            for i in range(0, len(level), 2)
        ]
    return path


def verify_inclusion(leaf: bytes, path, root: bytes) -> bool:
    """参考验真：按兄弟路径从叶摘要复算到根并比对（供测试 / 文档示例）。"""
    current = leaf
    for side, sibling in path:
        if side == "left":
            current = node_hash(sibling, current)
        elif side == "right":
            current = node_hash(current, sibling)
        else:
            raise ValueError(f"未知路径方向：{side!r}")
    return current == root
