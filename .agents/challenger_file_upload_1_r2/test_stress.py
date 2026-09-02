import pytest
from unittest.mock import MagicMock
import json

from argus.collectors.file_upload import (
    FileUploadCollector,
    FileUploadPayloadGenerator,
    FileUploadProber,
    FileUploadAnalyzer,
    FileUploadProbe,
    FileUploadResponse,
    FileUploadResult,
    FileUploadSeverity,
    FileUploadTechnique,
    FileUploadMutationStrategy,
    TargetRuntime,
)
from argus.reporting.cvss import CVSSCalculator
from argus.runtime.mission import Mission
from argus.graph.graph import KnowledgeGraph

def test_unrestricted_payloads_all_runtimes():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_unrestricted_probes()
    runtimes = {p.target_runtime for p in probes}
    assert TargetRuntime.PHP in runtimes
    assert TargetRuntime.JSP in runtimes
    assert TargetRuntime.ASP_ASPX in runtimes
    assert TargetRuntime.PYTHON in runtimes
    assert TargetRuntime.RUBY in runtimes
    assert TargetRuntime.BASH in runtimes
    assert TargetRuntime.GENERIC in runtimes

def test_mime_type_bypass_mutations():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_mime_bypass_probes()
    assert len(probes) >= 10
    valid_exec = ('.php', '.phtml', '.jsp', '.asp', '.aspx', '.py', '.rb', '.sh')
    for p in probes:
        assert any(p.filename.endswith(ext) for ext in valid_exec)
        assert p.content_type in ('image/jpeg', 'image/png', 'image/gif', 'application/pdf')
        assert p.strategy == FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH

def test_double_extension_probes():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_double_extension_probes()
    filenames = [p.filename for p in probes]
    assert len(probes) >= 3
    assert 'payload.aspx.gif' in filenames
    assert 'shell.php.jpg' in filenames
    assert 'payload.asp.png' in filenames
    assert 'exploit.jsp.gif' in filenames

def test_polyglot_9_configurations():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_polyglot_probes()
    assert len(probes) == 9
    for p in probes:
        assert isinstance(p.content, bytes)
        assert p.technique == FileUploadTechnique.POLYGLOT_MAGIC_BYTES
        assert p.strategy == FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING

def test_path_traversal_variations():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_path_traversal_probes()
    filenames = [p.filename for p in probes]
    assert any('../' in fn for fn in filenames)
    assert any(chr(92) in fn for fn in filenames)
    assert any('%2f' in fn or '%c0%af' in fn for fn in filenames)

def test_evasion_mutations_and_apply_mutation():
    gen = FileUploadPayloadGenerator()
    base = FileUploadProbe(
        filename='test.php',
        content='<?php echo 1; ?>',
        content_type='application/x-php',
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
    )
    cased = gen.apply_mutation(base, FileUploadMutationStrategy.EXTENSION_CASING)
    assert cased.filename.lower() == 'test.php' and cased.filename != 'test.php'

    nulled = gen.apply_mutation(base, FileUploadMutationStrategy.NULL_BYTE)
    assert '%00' in nulled.filename

    mismatch = gen.apply_mutation(base, FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH)
    assert mismatch.content_type == 'image/jpeg'

    magic = gen.apply_mutation(base, FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING)
    assert magic.content.startswith(b'GIF89a')

    enc = gen.apply_mutation(base, FileUploadMutationStrategy.FILENAME_ENCODING)
    assert '%2e' in enc.filename

    trailing = gen.apply_mutation(base, FileUploadMutationStrategy.TRAILING_DOTS_SPACES)
    assert trailing.filename.endswith('.')

    ntfs = gen.apply_mutation(base, FileUploadMutationStrategy.NTFS_STREAM)
    assert '::' in ntfs.filename

def test_storage_path_extraction_and_web_shell():
    prober = FileUploadProber()
    # Location header
    r1 = FileUploadResponse(status_code=201, headers={'Location': '/files/s.php'})
    prober._extract_storage_information(r1, 'https://example.com/upload', 's.php')
    assert r1.storage_url == 'https://example.com/files/s.php'

    # JSON body URL prioritization
    r2 = FileUploadResponse(
        status_code=200,
        body=json.dumps({'file_url': 'https://cdn.example.com/s.jsp', 'path': '/var/www/uploads/s.jsp'}),
    )
    prober._extract_storage_information(r2, 'https://example.com/upload', 's.jsp')
    assert r2.storage_url == 'https://cdn.example.com/s.jsp'
    assert r2.storage_path_disclosed == '/var/www/uploads/s.jsp'

    # Web shell canary execution
    mock_client = MagicMock()
    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.body = 'ARGUS_CANARY_TEST'
    mock_client.get.return_value = mock_get

    p_client = FileUploadProber(client=mock_client)
    r_shell = FileUploadResponse(status_code=200, storage_url='https://example.com/s.php')
    p_client._check_web_shell_reachability(None, r_shell, 'ARGUS_CANARY_TEST')
    assert r_shell.web_shell_executed is True
    assert r_shell.is_reflected is True

def test_false_positive_and_error_disclosure():
    analyzer = FileUploadAnalyzer()
    gen = FileUploadPayloadGenerator()
    mal_probe = gen.generate_unrestricted_probes()[0]

    # Benign probe rejected
    benign_probe = gen.generate_benign_probes()[0]
    assert analyzer.evaluate_probe(benign_probe, FileUploadResponse(status_code=200, body='OK'), 'https://example.com') is None

    # Error 500 stack trace NOT rejected, reported as CWE-200 / MEDIUM
    res_500 = analyzer.evaluate_probe(
        mal_probe,
        FileUploadResponse(status_code=500, body='Fatal error: Exception in /var/www/upload.php on line 12'),
        'https://example.com'
    )
    assert res_500 is not None
    assert res_500.cwe_id == 'CWE-200'
    assert res_500.severity == 'medium'

    # Safe UUID rename rejected
    res_uuid = analyzer.evaluate_probe(
        mal_probe,
        FileUploadResponse(
            status_code=200,
            storage_url='https://example.com/uploads/12345678-1234-1234-1234-123456789abc.png',
        ),
        'https://example.com'
    )
    assert res_uuid is None
