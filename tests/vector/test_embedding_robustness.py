"""
Robustness and adversarial stress tests for DeterministicEmbeddingProvider and VectorStore (Sprint 31c).

Covers:
- Unicode Normalization (NFC, NFD, NFKC, NFKD, CJK, Arabic, emoji, zero-width)
- Null and Control Characters
- Extreme Length Inputs (empty, single char, 100K chars)
- Homoglyph Attacks (Latin vs Cyrillic, lookalike domains)
- Security Taxonomy Coverage (synonym pairs, multi-word phrases, abbreviations)
- Determinism & Idempotency
- Distance Metric Consistency
"""

from __future__ import annotations

import unicodedata
import numpy as np
import pytest

from argus.vector.embeddings import DeterministicEmbeddingProvider, EmbeddingEngine
from argus.vector.models import DistanceMetric


@pytest.fixture
def provider() -> DeterministicEmbeddingProvider:
    return DeterministicEmbeddingProvider(dimension=384, seed=42)


@pytest.fixture
def engine(provider: DeterministicEmbeddingProvider) -> EmbeddingEngine:
    return EmbeddingEngine(provider=provider, dimension=384)


# ==============================================================================
# Unicode Normalization (3 tests)
# ==============================================================================


def test_unicode_normalization_forms(provider: DeterministicEmbeddingProvider):
    """Test NFC vs NFD vs NFKC vs NFKD normalized versions produce valid normalized vectors."""
    base_text = "résumé déjà vu café ℌ"
    s_nfc = unicodedata.normalize("NFC", base_text)
    s_nfd = unicodedata.normalize("NFD", base_text)
    s_nfkc = unicodedata.normalize("NFKC", base_text)
    s_nfkd = unicodedata.normalize("NFKD", base_text)

    v_nfc = provider.embed_text(s_nfc)
    v_nfd = provider.embed_text(s_nfd)
    v_nfkc = provider.embed_text(s_nfkc)
    v_nfkd = provider.embed_text(s_nfkd)

    for v in (v_nfc, v_nfd, v_nfkc, v_nfkd):
        assert len(v) == 384
        assert np.isfinite(v).all()
        norm = np.linalg.norm(v)
        assert np.isclose(norm, 1.0, atol=1e-5)


def test_unicode_normalization_cjk_arabic_emoji(provider: DeterministicEmbeddingProvider):
    """Test CJK characters, Arabic text, and emoji sequences produce valid vectors."""
    text = "測試 😃 مرحبا 💉 👾 🔥 \u0627\u0644\u0623\u0645\u0646"
    v = provider.embed_text(text)
    assert len(v) == 384
    assert np.isfinite(v).all()
    norm = np.linalg.norm(v)
    assert np.isclose(norm, 1.0, atol=1e-5)


def test_unicode_normalization_zero_width(provider: DeterministicEmbeddingProvider):
    """Test strings with zero-width joiners, zero-width non-joiners, and zero-width spaces."""
    s1 = "security"
    s2 = "se\u200bcurity\u200c\u200d"  # ZWSP, ZWNJ, ZWJ
    v1 = provider.embed_text(s1)
    v2 = provider.embed_text(s2)

    assert len(v1) == 384
    assert len(v2) == 384
    assert np.isfinite(v1).all()
    assert np.isfinite(v2).all()
    assert np.isclose(np.linalg.norm(v1), 1.0, atol=1e-5)
    assert np.isclose(np.linalg.norm(v2), 1.0, atol=1e-5)


# ==============================================================================
# Null and Control Characters (2 tests)
# ==============================================================================


def test_control_characters_null_and_range(provider: DeterministicEmbeddingProvider):
    """Test strings containing null byte, ASCII control characters (0x01-0x1f), and DEL (0x7f)."""
    control_chars = "".join(chr(c) for c in range(1, 32))
    text = f"prefix\x00{control_chars}middle\x7fsuffix"
    v = provider.embed_text(text)

    assert len(v) == 384
    assert np.isfinite(v).all()
    assert np.isclose(np.linalg.norm(v), 1.0, atol=1e-5)


def test_control_characters_bom_and_formatting(provider: DeterministicEmbeddingProvider):
    """Test strings containing UTF-8 BOM, vertical tabs, form feeds, and line separators."""
    text = "\ufeff\x0b\x0c\u2028\u2029secret_token_123"
    v = provider.embed_text(text)

    assert len(v) == 384
    assert np.isfinite(v).all()
    assert np.isclose(np.linalg.norm(v), 1.0, atol=1e-5)


# ==============================================================================
# Extreme Length Inputs (2 tests)
# ==============================================================================


def test_extreme_length_empty_and_single_char(provider: DeterministicEmbeddingProvider):
    """Test embedding empty string and single character produces valid 384-d normalized vectors."""
    v_empty = provider.embed_text("")
    assert len(v_empty) == 384
    assert np.isfinite(v_empty).all()
    assert np.isclose(np.linalg.norm(v_empty), 1.0, atol=1e-5)

    v_ws = provider.embed_text("   \t\n  ")
    assert len(v_ws) == 384
    assert np.isclose(np.linalg.norm(v_ws), 1.0, atol=1e-5)

    v_single = provider.embed_text("a")
    assert len(v_single) == 384
    assert np.isfinite(v_single).all()
    assert np.isclose(np.linalg.norm(v_single), 1.0, atol=1e-5)


def test_extreme_length_100k_characters(provider: DeterministicEmbeddingProvider):
    """Test embedding 100K+ character string executes without memory error or overflow."""
    huge_text = ("vulnerability report buffer overflow heap corruption " * 2000)[:105000]
    v = provider.embed_text(huge_text)

    assert len(v) == 384
    assert np.isfinite(v).all()
    assert np.isclose(np.linalg.norm(v), 1.0, atol=1e-5)


# ==============================================================================
# Homoglyph Attacks (2 tests)
# ==============================================================================


def test_homoglyph_attacks_latin_vs_cyrillic(provider: DeterministicEmbeddingProvider):
    """Verify visually identical Latin and Cyrillic characters produce distinct vectors."""
    # Latin 'a' (U+0061) vs Cyrillic 'а' (U+0430)
    s_latin = "admin"
    s_cyrillic = "\u0430dmin"

    v_latin = provider.embed_text(s_latin)
    v_cyrillic = provider.embed_text(s_cyrillic)

    assert v_latin != v_cyrillic


def test_homoglyph_attacks_lookalike_domains(provider: DeterministicEmbeddingProvider):
    """Verify lookalike domain names produce distinct embedding vectors."""
    s1 = "bank-login.com"
    s2 = "b\u0430nk-login.com"  # Cyrillic 'а' in bank
    s3 = "bank-1ogin.com"      # Digit 1 instead of 'l'

    v1 = provider.embed_text(s1)
    v2 = provider.embed_text(s2)
    v3 = provider.embed_text(s3)

    assert v1 != v2
    assert v1 != v3
    assert v2 != v3


# ==============================================================================
# Security Taxonomy Coverage (3 tests)
# ==============================================================================


def test_security_taxonomy_synonym_pairs(engine: EmbeddingEngine):
    """Verify synonym pairs from SECURITY_TAXONOMY have significantly higher similarity than unrelated pairs."""
    # SQLi synonyms
    v_sqli = engine.embed_text("sqli")
    v_sql_inj = engine.embed_text("sql injection")
    v_unrelated = engine.embed_text("astronomy astrophysics telescope galaxy")

    sim_syn = engine.similarity(v_sqli, v_sql_inj)
    sim_diff = engine.similarity(v_sqli, v_unrelated)

    assert sim_syn > sim_diff
    assert sim_syn > 0.45


def test_security_taxonomy_multi_word_concepts(engine: EmbeddingEngine):
    """Verify multi-word concept phrases (cross-site scripting, remote code execution) are recognized."""
    v_xss_full = engine.embed_text("cross site scripting")
    v_xss_short = engine.embed_text("xss")
    v_rce = engine.embed_text("remote code execution")

    sim_xss = engine.similarity(v_xss_full, v_xss_short)
    sim_cross = engine.similarity(v_xss_full, v_rce)

    assert sim_xss > 0.5
    assert sim_xss > sim_cross


def test_security_taxonomy_abbreviations_mapping(engine: EmbeddingEngine):
    """Verify security abbreviations map correctly to their full technical representations."""
    pairs = [
        ("rce", "remote code execution"),
        ("sqli", "sql injection"),
        ("ssrf", "server side request forgery"),
        ("idor", "insecure direct object reference"),
    ]

    for abbr, full in pairs:
        v_abbr = engine.embed_text(abbr)
        v_full = engine.embed_text(full)
        sim = engine.similarity(v_abbr, v_full)
        assert sim > 0.45, f"Expected higher similarity for pair ({abbr}, {full}), got {sim}"


# ==============================================================================
# Determinism & Idempotency (2 tests)
# ==============================================================================


def test_determinism_idempotency_repeated_calls(provider: DeterministicEmbeddingProvider):
    """Verify embed_text called 100 times with identical input yields bit-identical vectors."""
    text = "deterministic repeatable security analysis payload"
    first_vector = provider.embed_text(text)

    for _ in range(100):
        current_vector = provider.embed_text(text)
        assert current_vector == first_vector


def test_determinism_batch_vs_single(provider: DeterministicEmbeddingProvider):
    """Verify embed_batch yields bit-identical results compared to individual embed_text calls."""
    texts = [
        "SQL injection union select database bypass",
        "Stored cross site scripting in comments bio",
        "Command execution reverse shell payload",
        "Server side request forgery AWS metadata",
    ]

    batch_vectors = provider.embed_batch(texts)
    single_vectors = [provider.embed_text(t) for t in texts]

    assert len(batch_vectors) == len(texts)
    assert batch_vectors == single_vectors


# ==============================================================================
# Distance Metric Consistency (2 tests)
# ==============================================================================


def test_distance_metric_consistency_self_similarity(engine: EmbeddingEngine):
    """Verify cosine similarity of a vector with itself is 1.0."""
    texts = [
        "Remote code execution via yaml deserialization",
        "Insecure direct object reference in invoice download",
        "Cross site request forgery anti csrf token missing",
    ]

    for t in texts:
        v = engine.embed_text(t)
        sim = engine.similarity(v, v, metric=DistanceMetric.COSINE)
        assert np.isclose(sim, 1.0, atol=1e-5)


def test_distance_metric_consistency_bounds_and_ordering(engine: EmbeddingEngine):
    """Verify cosine similarity is strictly in [0, 1] range and reflects semantic affinity."""
    v_query = engine.embed_text("union based sql injection")
    v_related = engine.embed_text("database sql injection vulnerability in parameter")
    v_unrelated = engine.embed_text("baking artisan sourdough bread with flour and water")

    sim_related = engine.similarity(v_query, v_related)
    sim_unrelated = engine.similarity(v_query, v_unrelated)

    assert 0.0 <= sim_related <= 1.0
    assert 0.0 <= sim_unrelated <= 1.0
    assert sim_related > sim_unrelated
