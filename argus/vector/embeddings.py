"""Embedding engine and providers for ARGUS vector search."""

from abc import ABC, abstractmethod
import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Union

import numpy as np

from argus.vector.exceptions import DimensionMismatchError, EmbeddingError
from argus.vector.models import DistanceMetric


class BaseEmbeddingProvider(ABC):
    """Abstract base class for vector embedding providers."""

    def __init__(self, dimension: int = 384):
        self._dimension = dimension

    @property
    def dimension(self) -> int:
        """Return the dimensionality of the generated embeddings."""
        return self._dimension

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider identifier name."""
        pass

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Generate a vector embedding for a single text."""
        pass

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate vector embeddings for a list of texts."""
        return [self.embed_text(t) for t in texts]


class DeterministicEmbeddingProvider(BaseEmbeddingProvider):
    """
    Fast, 100% offline, zero-dependency semantic feature hashing & n-gram projector.
    
    Combines:
    1. Lexical word tokens & subword n-grams (3-4 chars) with hash-based projection.
    2. Deep cybersecurity taxonomy concept clusters mapping semantically related terms
       (e.g., 'SQLi' <-> 'SQL Injection', 'XSS' <-> 'Cross-Site Scripting', 'RCE' <-> 'Command Execution').
    3. Multi-phrase concept recognition and morphological lemma normalization.
    4. Locality-sensitive pseudo-random Gaussian projections with L2 unit normalization.
    """

    # Comprehensive security semantic concept clusters
    SECURITY_TAXONOMY: Dict[str, int] = {
        # Cluster 1: SQL Injection & Database Exploits
        "sql": 1, "sqli": 1, "injection": 1, "inject": 1, "injected": 1, "injections": 1,
        "union_select": 1, "blind_sqli": 1, "time_based": 1, "error_based": 1, "sqlmap": 1,
        "database_injection": 1, "dbms": 1, "database": 1, "databases": 1, "sqlite": 1,
        "mysql": 1, "postgres": 1, "postgresql": 1, "oracle": 1, "mssql": 1, "nosql": 1,
        "nosql_injection": 1, "xpath_injection": 1, "ldap_injection": 1, "orm_injection": 1,
        "sql_injection": 1, "database_exploit": 1, "cwe_89": 1, "cwe89": 1,

        # Cluster 2: Cross-Site Scripting & Client-side Attacks
        "xss": 2, "cross_site_scripting": 2, "cross_site": 2, "scripting": 2, "script": 2,
        "scripts": 2, "reflected_xss": 2, "stored_xss": 2, "dom_xss": 2, "script_injection": 2,
        "html_injection": 2, "svg_injection": 2, "polyglot": 2, "javascript": 2,
        "payload_alert": 2, "alert": 2, "document_cookie": 2, "dom_clobbering": 2, "dom": 2,
        "cwe_79": 2, "cwe79": 2,

        # Cluster 3: Remote Code Execution & Command Injection
        "rce": 3, "remote_code_execution": 3, "code_execution": 3, "command_injection": 3,
        "shell_injection": 3, "arbitrary_code": 3, "reverse_shell": 3, "bind_shell": 3,
        "popen": 3, "system_call": 3, "eval_injection": 3, "os_command": 3, "code_injection": 3,
        "command": 3, "commands": 3, "shell": 3, "exec": 3, "execution": 3, "cwe_78": 3, "cwe78": 3,

        # Cluster 4: Authentication, Authorization & Session Flaws
        "auth": 4, "authentication": 4, "authorization": 4, "bypass": 4, "bypassed": 4,
        "login": 4, "credential": 4, "credentials": 4, "password": 4, "passwords": 4,
        "token": 4, "tokens": 4, "jwt": 4, "session": 4, "sessions": 4, "session_fixation": 4,
        "session_hijacking": 4, "cookie": 4, "oauth": 4, "saml": 4, "mfa": 4, "2fa": 4,
        "brute_force": 4, "weak_password": 4, "hardcoded_secret": 4, "cwe_287": 4, "cwe287": 4,

        # Cluster 5: Path Traversal, File Inclusion & Information Disclosure
        "traversal": 5, "path_traversal": 5, "directory_traversal": 5, "lfi": 5, "rfi": 5,
        "local_file_inclusion": 5, "file_read": 5, "arbitrary_file_read": 5, "dot_dot_slash": 5,
        "etc_passwd": 5, "passwd": 5, "file_disclosure": 5, "source_code_disclosure": 5,
        "leak": 5, "traversals": 5, "cwe_22": 5, "cwe22": 5,

        # Cluster 6: CSRF & Request Forgery
        "csrf": 6, "cross_site_request_forgery": 6, "xsrf": 6, "anti_csrf": 6, "samesite": 6,
        "cwe_352": 6, "cwe352": 6,

        # Cluster 7: SSRF & Cloud Metadata
        "ssrf": 7, "server_side_request_forgery": 7, "cloud_metadata": 7, "aws_metadata": 7,
        "169_254_169_254": 7, "oob": 7, "out_of_band": 7, "imds": 7, "cwe_918": 7, "cwe918": 7,

        # Cluster 8: IDOR & Broken Access Control
        "idor": 8, "insecure_direct_object_reference": 8, "broken_object_level_authorization": 8,
        "bola": 8, "bfla": 8, "privilege_escalation": 8, "privesc": 8, "horizontal_privilege": 8,
        "vertical_privilege": 8, "unauthorized_access": 8, "access_control": 8,
        "privilege": 8, "privileges": 8, "spooler": 8, "print_spooler": 8, "printnightmare": 8,
        "cwe_269": 8, "cwe269": 8, "cwe_639": 8, "cwe639": 8, "cwe_862": 8, "cwe862": 8,

        # Cluster 9: Insecure Deserialization & Object Injection
        "deserialization": 9, "insecure_deserialization": 9, "pickle": 9, "java_deserialization": 9,
        "ysoserial": 9, "gadget_chain": 9, "yaml_load": 9, "untrusted_data": 9,
        "jndi": 9, "jndi_injection": 9, "ldap": 9, "log4j": 9, "log4shell": 9, "spring4shell": 9,
        "cwe_502": 9, "cwe502": 9,

        # Cluster 10: Cryptographic Issues & Weak Encryption
        "crypto": 10, "cryptography": 10, "weak_cipher": 10, "weak_crypto": 10, "padding_oracle": 10,
        "ecb_mode": 10, "md5_hash": 10, "sha1": 10, "rsa_small_e": 10, "weak_key": 10, "tls": 10,
        "ssl": 10, "certificate": 10, "cwe_327": 10, "cwe327": 10,

        # Cluster 11: Denial of Service & Resource Exhaustion
        "dos": 11, "denial_of_service": 11, "ddos": 11, "resource_exhaustion": 11, "redos": 11,
        "zip_bomb": 11, "billion_laughs": 11, "slowloris": 11, "rate_limit": 11,
        "cwe_400": 11, "cwe400": 11,

        # Cluster 12: Memory Corruption & Binary Exploitation
        "overflow": 12, "buffer_overflow": 12, "stack_overflow": 12, "heap_overflow": 12,
        "use_after_free": 12, "uaf": 12, "format_string": 12, "out_of_bounds": 12, "rop": 12,
        "shellcode": 12, "aslr_bypass": 12, "dep_bypass": 12, "null_dereference": 12,
        "cwe_119": 12, "cwe119": 12, "cwe_416": 12, "cwe416": 12,

        # Cluster 13: Reconnaissance, Discovery & Port Scanning
        "recon": 13, "reconnaissance": 13, "subdomain": 13, "dns": 13, "port_scan": 13,
        "open_port": 13, "service_detection": 13, "banner_grab": 13, "nmap": 13, "whois": 13,
        "fingerprint": 13, "discovery": 13, "asset": 13, "endpoint": 13, "crawler": 13,

        # Cluster 14: Severity & Risk Terminology
        "critical": 14, "high": 14, "medium": 14, "low": 14, "info": 14, "cvss": 14,
        "exploit": 14, "exploitable": 14, "proof_of_concept": 14, "poc": 14, "weaponized": 14,
        "vulnerability": 14, "vulnerabilities": 14, "vulnerable": 14, "flaw": 14, "threat": 14,

        # Cluster 15: Network & Protocol Vulnerabilities
        "smb": 15, "rdp": 15, "ssh": 15, "ftp": 15, "telnet": 15, "snmp": 15, "mitm": 15,
        "arp_spoof": 15, "dns_cache_poisoning": 15, "packet_inspection": 15, "protocol": 15,
    }

    # Morphological lemmas mapping to standard roots
    LEMMAS: Dict[str, str] = {
        "injections": "inject", "injection": "inject", "injecting": "inject", "injected": "inject",
        "scripting": "script", "scripts": "script",
        "traversals": "traversal", "traversing": "traversal", "traversed": "traversal",
        "executions": "exec", "execution": "exec", "executing": "exec", "executed": "exec",
        "bypasses": "bypass", "bypassing": "bypass", "bypassed": "bypass",
        "vulnerabilities": "vulnerability", "vulnerable": "vulnerability",
        "databases": "database", "queries": "query",
        "parameters": "parameter", "params": "parameter", "param": "parameter",
        "payloads": "payload", "exploits": "exploit", "exploiting": "exploit", "exploited": "exploit",
    }

    def __init__(self, dimension: int = 384, seed: int = 42):
        super().__init__(dimension=dimension)
        self.seed = seed
        self._init_projections()

    def _init_projections(self):
        """Initialize fixed pseudo-random projection bases for repeatable vector spaces."""
        rng = np.random.RandomState(self.seed)
        self._vocab_size = 8192
        self._ngram_size = 8192
        self._concept_size = 256

        # Basis projections (unit-scaled)
        self._word_proj = rng.randn(self._vocab_size, self._dimension).astype(np.float32)
        self._ngram_proj = rng.randn(self._ngram_size, self._dimension).astype(np.float32)
        self._concept_proj = rng.randn(self._concept_size, self._dimension).astype(np.float32)

        # Normalize projection matrices rows to unit norm
        self._word_proj /= (np.linalg.norm(self._word_proj, axis=1, keepdims=True) + 1e-10)
        self._ngram_proj /= (np.linalg.norm(self._ngram_proj, axis=1, keepdims=True) + 1e-10)
        self._concept_proj /= (np.linalg.norm(self._concept_proj, axis=1, keepdims=True) + 1e-10)

    @property
    def provider_name(self) -> str:
        return "deterministic"

    def _normalize_text(self, text: str) -> str:
        """Convert camelCase, hyphens, and non-alphanumeric to spaced lowercase."""
        if not text:
            return ""
        s1 = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
        s2 = re.sub(r"[^a-zA-Z0-9]", " ", s1.lower())
        return s2

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into canonical lemma tokens."""
        norm = self._normalize_text(text)
        raw_tokens = [t.strip() for t in norm.split() if len(t.strip()) > 0]
        tokens = []
        for t in raw_tokens:
            stemmed = self.LEMMAS.get(t, t)
            tokens.append(stemmed)
        return tokens

    def _hash_token(self, token: str, table_size: int) -> int:
        """Fast deterministic MD5 hash mapping to table slot."""
        h = hashlib.md5(token.encode("utf-8")).hexdigest()
        return int(h, 16) % table_size

    def embed_text(self, text: str) -> List[float]:
        """Generate normalized 384-d semantic embedding from text."""
        if not text or not text.strip():
            vec = np.ones(self._dimension, dtype=np.float32)
            vec /= np.linalg.norm(vec)
            return vec.tolist()

        norm_text = self._normalize_text(text)
        tokens = self._tokenize(text)
        if not tokens:
            vec = np.ones(self._dimension, dtype=np.float32)
            vec /= np.linalg.norm(vec)
            return vec.tolist()

        vec = np.zeros(self._dimension, dtype=np.float32)

        token_counts: Dict[str, int] = {}
        for t in tokens:
            token_counts[t] = token_counts.get(t, 0) + 1

        for token, count in token_counts.items():
            tf_weight = 1.0 + math.log(count)

            # 1. Word token projection
            w_idx = self._hash_token(token, self._vocab_size)
            vec += self._word_proj[w_idx] * (tf_weight * 1.5)

            # 2. Semantic taxonomy concept projection
            if token in self.SECURITY_TAXONOMY:
                c_idx = self.SECURITY_TAXONOMY[token] % self._concept_size
                vec += self._concept_proj[c_idx] * (tf_weight * 8.0)

            # 3. Subword n-grams (3 and 4 chars)
            if len(token) >= 3:
                for n in (3, 4):
                    if len(token) >= n:
                        for i in range(len(token) - n + 1):
                            ngram = token[i:i+n]
                            ng_idx = self._hash_token(ngram, self._ngram_size)
                            vec += self._ngram_proj[ng_idx] * (tf_weight * 0.3)

        # 4. Multi-word concept phrases in normalized text
        for phrase, concept_idx in self.SECURITY_TAXONOMY.items():
            if "_" in phrase:
                search_phrase = phrase.replace("_", " ")
                if search_phrase in norm_text:
                    c_idx = concept_idx % self._concept_size
                    vec += self._concept_proj[c_idx] * 12.0

        # L2 normalize
        norm = float(np.linalg.norm(vec))
        if norm > 1e-12:
            vec = vec / norm
        else:
            vec = np.ones(self._dimension, dtype=np.float32)
            vec /= np.linalg.norm(vec)

        return vec.astype(float).tolist()

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate normalized embeddings for a batch of texts."""
        return [self.embed_text(t) for t in texts]


class FastEmbedProvider(BaseEmbeddingProvider):
    """Optional FastEmbed provider using lightweight ONNX models."""

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5", dimension: int = 384):
        super().__init__(dimension=dimension)
        self.model_name = model_name
        self._model = None
        self._init_model()

    def _init_model(self):
        try:
            from fastembed import TextEmbedding
            self._model = TextEmbedding(model_name=self.model_name)
        except ImportError as e:
            raise EmbeddingError(f"fastembed package is not installed: {e}")
        except Exception as e:
            raise EmbeddingError(f"Failed to initialize FastEmbed model '{self.model_name}': {e}")

    @property
    def provider_name(self) -> str:
        return "fastembed"

    @classmethod
    def is_available(cls) -> bool:
        try:
            import fastembed
            return True
        except ImportError:
            return False

    def embed_text(self, text: str) -> List[float]:
        if self._model is None:
            self._init_model()
        try:
            embeddings = list(self._model.embed([text]))
            return embeddings[0].tolist()
        except Exception as e:
            raise EmbeddingError(f"FastEmbed embedding generation failed: {e}")

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if self._model is None:
            self._init_model()
        try:
            embeddings = list(self._model.embed(texts))
            return [emb.tolist() for emb in embeddings]
        except Exception as e:
            raise EmbeddingError(f"FastEmbed batch embedding generation failed: {e}")


class SentenceTransformerProvider(BaseEmbeddingProvider):
    """Optional SentenceTransformer provider using local HuggingFace models."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2", dimension: int = 384):
        super().__init__(dimension=dimension)
        self.model_name = model_name
        self._model = None
        self._init_model()

    def _init_model(self):
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
        except ImportError as e:
            raise EmbeddingError(f"sentence-transformers package is not installed: {e}")
        except Exception as e:
            raise EmbeddingError(f"Failed to initialize SentenceTransformer '{self.model_name}': {e}")

    @property
    def provider_name(self) -> str:
        return "sentence_transformers"

    @classmethod
    def is_available(cls) -> bool:
        try:
            import sentence_transformers
            return True
        except ImportError:
            return False

    def embed_text(self, text: str) -> List[float]:
        if self._model is None:
            self._init_model()
        try:
            emb = self._model.encode(text, normalize_embeddings=True)
            return emb.tolist()
        except Exception as e:
            raise EmbeddingError(f"SentenceTransformer embedding generation failed: {e}")

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if self._model is None:
            self._init_model()
        try:
            embeddings = self._model.encode(texts, normalize_embeddings=True)
            return [emb.tolist() for emb in embeddings]
        except Exception as e:
            raise EmbeddingError(f"SentenceTransformer batch embedding generation failed: {e}")


class EmbeddingEngine:
    """
    Unified embedding engine orchestrating embedding generation and similarity metrics.
    """

    def __init__(
        self,
        provider: Optional[Union[BaseEmbeddingProvider, str]] = "auto",
        dimension: int = 384,
    ):
        self._dimension = dimension
        if isinstance(provider, BaseEmbeddingProvider):
            self._provider = provider
            self._dimension = provider.dimension
        else:
            self._provider = self._resolve_provider(str(provider or "auto").lower(), dimension)

    def _resolve_provider(self, provider_str: str, dimension: int) -> BaseEmbeddingProvider:
        """Resolve and instantiate the requested or best-available embedding provider."""
        if provider_str in ("deterministic", "local", "offline"):
            return DeterministicEmbeddingProvider(dimension=dimension)
        elif provider_str == "fastembed":
            return FastEmbedProvider(dimension=dimension)
        elif provider_str in ("sentence_transformers", "sentence-transformers"):
            return SentenceTransformerProvider(dimension=dimension)
        elif provider_str == "auto":
            if FastEmbedProvider.is_available():
                try:
                    return FastEmbedProvider(dimension=dimension)
                except Exception:
                    pass
            if SentenceTransformerProvider.is_available():
                try:
                    return SentenceTransformerProvider(dimension=dimension)
                except Exception:
                    pass
            # Default to robust offline deterministic engine
            return DeterministicEmbeddingProvider(dimension=dimension)
        else:
            raise EmbeddingError(f"Unknown embedding provider: '{provider_str}'")

    @property
    def provider(self) -> BaseEmbeddingProvider:
        """Return the active underlying embedding provider."""
        return self._provider

    @property
    def provider_name(self) -> str:
        """Return the active provider's name."""
        return self._provider.provider_name

    @property
    def dimension(self) -> int:
        """Return the embedding dimensionality."""
        return self._dimension

    def embed_text(self, text: str) -> List[float]:
        """Embed a single string."""
        emb = self._provider.embed_text(text)
        if len(emb) != self._dimension:
            raise DimensionMismatchError(
                f"Embedding dimension {len(emb)} does not match expected {self._dimension}"
            )
        return emb

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed a batch of strings."""
        embeddings = self._provider.embed_batch(texts)
        for i, emb in enumerate(embeddings):
            if len(emb) != self._dimension:
                raise DimensionMismatchError(
                    f"Embedding at index {i} has dimension {len(emb)}, expected {self._dimension}"
                )
        return embeddings

    def similarity(
        self,
        vec1: List[float],
        vec2: List[float],
        metric: Union[DistanceMetric, str] = DistanceMetric.COSINE,
    ) -> float:
        """
        Compute similarity score between two embedding vectors.
        Returns a score in range [0.0, 1.0] where 1.0 means identical.
        """
        if len(vec1) != len(vec2):
            raise DimensionMismatchError(
                f"Vector lengths do not match: {len(vec1)} vs {len(vec2)}"
            )

        v1 = np.array(vec1, dtype=np.float32)
        v2 = np.array(vec2, dtype=np.float32)

        if isinstance(metric, str):
            metric = DistanceMetric.from_str(metric)

        if metric == DistanceMetric.COSINE:
            norm1 = float(np.linalg.norm(v1))
            norm2 = float(np.linalg.norm(v2))
            if norm1 < 1e-12 or norm2 < 1e-12:
                return 0.0
            dot = float(np.dot(v1, v2)) / (norm1 * norm2)
            score = max(0.0, min(1.0, dot))
            return score
        elif metric == DistanceMetric.L2:
            diff = v1 - v2
            dist = float(np.linalg.norm(diff))
            return 1.0 / (1.0 + dist)
        elif metric == DistanceMetric.DOT:
            dot = float(np.dot(v1, v2))
            return dot
        else:
            raise ValueError(f"Unsupported metric: {metric}")


_GLOBAL_EMBEDDING_ENGINE: Optional[EmbeddingEngine] = None


def get_embedding_engine(
    provider: str = "auto",
    dimension: int = 384,
    force_new: bool = False,
) -> EmbeddingEngine:
    """
    Get or create singleton/cached EmbeddingEngine instance.
    """
    global _GLOBAL_EMBEDDING_ENGINE
    if _GLOBAL_EMBEDDING_ENGINE is None or force_new:
        _GLOBAL_EMBEDDING_ENGINE = EmbeddingEngine(provider=provider, dimension=dimension)
    return _GLOBAL_EMBEDDING_ENGINE
