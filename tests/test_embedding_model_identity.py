# -*- coding: utf-8 -*-
"""Vectors from one embedding model must never be reused by another.

    pytest tests/test_embedding_model_identity.py -v

WHY THIS EXISTS

A vector only means anything next to other vectors from the same model. Swap
the embedding model and every stored vector becomes a measurement in different
units.

That failure is silent. Nothing raises, nothing logs, and cosine similarity
happily returns a number for two vectors that share a dimension and nothing
else -- so retrieval returns the wrong passages and the auditor reads findings
drawn from evidence that never matched the question. It is the same shape as
every other defect this product has shipped: it keeps working and it is wrong.

Three stores had to be taught the difference, and none of them knew it before:

  * the pickled cache, keyed (filename, chunk_index, content_hash) -- every
    field of which stays identical when the model changes
  * vec_chunks (sqlite-vec), keyed by chunk_id alone
  * pg_vec_chunks (pgvector), keyed by chunk_id alone

The dimension is not a guard either. Both native tables are declared at 768 to
match nomic-embed-text, so a different 768-dimension model is accepted without
complaint; only a model of some other width would fail loudly, and then for the
wrong reason.
"""
import io
import os
import re

import pytest

import src.core.retrieval as rx


RETRIEVAL_SRC = io.open(rx.__file__, encoding="utf-8").read()


def test_the_cache_key_carries_the_model():
    """Two models must not produce the same key for the same chunk."""
    key = rx._embed_cache_key("evidence.pdf", 3, "NTP synchronized: yes")
    assert rx.EMBEDDING_MODEL_ID in key, (
        "the embedding model is not part of the cache key, so a swapped model "
        "reuses the previous model's vectors -- see this module's docstring")


def test_the_same_chunk_keys_differently_under_a_different_model(monkeypatch):
    """The point of the key: change the model, lose the match."""
    args = ("evidence.pdf", 3, "NTP synchronized: yes")
    before = rx._embed_cache_key(*args)

    monkeypatch.setattr(rx, "EMBEDDING_MODEL_ID", "some-other-embedding-model")
    after = rx._embed_cache_key(*args)

    assert before != after, (
        "the same chunk keys identically under two different models, so the "
        "second model would read the first one's vectors")

    # And identical inputs under the same model must still share one entry --
    # the content-addressing that was there before is not lost.
    monkeypatch.setattr(rx, "EMBEDDING_MODEL_ID", "some-other-embedding-model")
    assert rx._embed_cache_key(*args) == after


def test_the_model_id_is_configurable_and_never_empty():
    """An operator swapping the model declares it; a blank value is not allowed
    to become the identity, because then every model looks like every other."""
    assert rx.EMBEDDING_MODEL_ID, "the embedding model id is empty"
    assert "EMBEDDING_MODEL_ID" in RETRIEVAL_SRC
    assert 'os.environ.get(\n    "EMBEDDING_MODEL_ID"' in RETRIEVAL_SRC or \
           'os.environ.get("EMBEDDING_MODEL_ID"' in RETRIEVAL_SRC


@pytest.mark.parametrize("engine,table,meta", [
    ("sqlite-vec", "vec_chunks", "vec_meta"),
    ("pgvector", "pg_vec_chunks", "pg_vec_meta"),
])
def test_each_native_store_is_stamped_and_cleared_on_change(engine, table, meta):
    """Both native tables are keyed by chunk_id, which is identical across
    models, so each keeps the model that built it beside it and empties itself
    when that changes. The vectors are derived data -- the chunks they came
    from are untouched, and the next search re-embeds what it needs."""
    assert meta in RETRIEVAL_SRC, "%s has no model stamp table (%s)" % (engine, meta)

    # The clear must be conditional on a CHANGE, not run on every start: an
    # unconditional wipe would re-embed the whole corpus at each restart.
    seg = RETRIEVAL_SRC[RETRIEVAL_SRC.index(meta):]
    seg = seg[:2500]
    assert "DELETE FROM %s" % table in seg, (
        "%s is never cleared when the embedding model changes" % table)
    assert "_stamped" in seg and "EMBEDDING_MODEL_ID" in seg, (
        "%s is cleared without comparing the stamp to the current model" % engine)


def test_a_change_is_announced_not_silent():
    """The operator gets told. Re-embedding a corpus is slow, and an unexplained
    slow first audit after an upgrade is how this gets misdiagnosed."""
    assert RETRIEVAL_SRC.count("embedding model changed") >= 2, (
        "both native stores should report a model change when they clear")
