import hashlib
import hmac
import platform
import random
import string
import time
import uuid
import pbkdf2
import pytest
from Obfuscatory import Obfuscatory


@pytest.mark.parametrize(
    "hash_algo_name, expected_digest_mod",
    [
        ("sha3_512", "sha3_512"),  # Happy path: Valid hash algorithm
        ("sha256", "sha256"),  # Happy path: Another valid hash algorithm
        (None, "sha3_512"),  # Edge case: None provided, defaults to sha3_512
        ("md5", "sha3_512"),  # Error case: Unsupported algorithm, defaults to sha3_512
        ("", "sha3_512"),  # Edge case: Empty string, defaults to sha3_512
    ],
    ids=["valid_sha3_512", "valid_sha256", "none_provided", "invalid_md5", "empty_string"],
)
def test_obfuscatory_init(hash_algo_name, expected_digest_mod):
    # Act
    obfuscator = Obfuscatory(hash_algo_name)
    # Assert
    assert obfuscator._digest_mod_ == expected_digest_mod


@pytest.mark.parametrize(
    "message, expected_anonymized",
    [
        ("test message", lambda x: x is not None),  # Happy path: Valid message
        ("", lambda x: x is not None),  # Edge case: Empty message
        (None, None),  # Error case: None message
    ],
    ids=["valid_message", "empty_message", "none_message"],
)
def test_anonymize(message, expected_anonymized):
    # Act
    anonymized_message = Obfuscatory.anonymize(message)
    # Assert
    assert expected_anonymized(anonymized_message)
    if anonymized_message:
        assert len(anonymized_message) == 128


@pytest.mark.parametrize(
    "message, key_name, expected_pseudo_anonymized",
    [
        ("test message", "test_key", lambda x: x is not None),  # Happy path: Valid message and key
        ("", "test_key", lambda x: x is not None),  # Edge case: Empty message, valid key
        (None, "test_key", None),  # Error case: None message, valid key
        ("test message", None, None),  # Error case: Valid message, None key
        ("test message", "invalid_key", None),  # Error case: Valid message, invalid key
    ],
    ids=[
        "valid_message_key",
        "empty_message_valid_key",
        "none_message_valid_key",
        "valid_message_none_key",
        "valid_message_invalid_key",
    ],
)
def test_pseudo_anonymize(message, key_name, expected_pseudo_anonymized, tmp_path):
    # Arrange
    keytab_file = tmp_path / "keytab.plist"
    keytab_file.write_text("test_key=test_value")
    obfuscator = Obfuscatory()
    obfuscator._keytab_file_name_ = str(keytab_file)
    obfuscator.load_key_from_file()
    # Act
    pseudo_anonymized_message = obfuscator.pseudo_anonymize(message, key_name)
    # Assert
    if callable(expected_pseudo_anonymized):
        assert expected_pseudo_anonymized(pseudo_anonymized_message)
        assert len(pseudo_anonymized_message) == 128
    else:
        assert pseudo_anonymized_message == expected_pseudo_anonymized


@pytest.mark.parametrize(
    "passphrase, expected_key",
    [
        ("test passphrase", lambda x: x is not None),  # Happy path: Valid passphrase
        ("", lambda x: x is not None),  # Edge case: Empty passphrase
        (None, lambda x: x is not None),  # Edge case: None passphrase
    ],
    ids=["valid_passphrase", "empty_passphrase", "none_passphrase"],
)
def test_generate_key(passphrase, expected_key):
    # Act
    key = Obfuscatory.generate_key(passphrase)
    # Assert
    assert expected_key(key)
    if key:
        assert len(key) == 128


@pytest.mark.parametrize(
    "keytab_content, expected_dict",
    [
        ("test_key=test_value\nanother_key=another_value", {"test_key": "test_value", "another_key": "another_value"}),  # Happy path: Valid content
        ("", {}),  # Edge case: Empty file
        ("test_key=test_value\n", {"test_key": "test_value"}),  # Edge case: Trailing newline
        ("test_key=  test_value  ", {"test_key": "  test_value  "}), # Edge case: Spaces around value
    ],
    ids=["valid_content", "empty_file", "trailing_newline", "spaces_around_value"]
)
def test_load_key_from_file(tmp_path, keytab_content, expected_dict):
    # Arrange
    keytab_file = tmp_path / "keytab.plist"
    keytab_file.write_text(keytab_content)
    obfuscator = Obfuscatory()
    obfuscator._keytab_file_name_ = str(keytab_file)
    # Act
    obfuscator.load_key_from_file()
    # Assert
    assert obfuscator._hash_dict_ == expected_dict



@pytest.mark.parametrize(
    "keytab_content, exception_type, expected_message",
    [
        ("test_key:test_value", SystemExit, "Either separator '=' is missing or encountered blank line in"), # Error case: Invalid separator
        ("=test_value", SystemExit, "Malformed keytab file. Please check"),  # Error case: Missing key
        ("test_key=", SystemExit, "Malformed keytab file. Please check"),  # Error case: Missing value
        ("test_key=test_value\n\nanother_key=another_value", SystemExit, "Either separator '=' is missing or encountered blank line in"), #Error case: Blank line
        ("test_key=test_value\n  \nanother_key=another_value", SystemExit, "Either separator '=' is missing or encountered blank line in"), #Error case: Blank line with spaces
    ],
    ids=["invalid_separator", "missing_key", "missing_value", "blank_line", "blank_line_with_spaces"]
)
def test_load_key_from_file_exceptions(tmp_path, keytab_content, exception_type, expected_message):
    # Arrange
    keytab_file = tmp_path / "keytab.plist"
    keytab_file.write_text(keytab_content)
    obfuscator = Obfuscatory()
    obfuscator._keytab_file_name_ = str(keytab_file)
    # Act and Assert
    with pytest.raises(exception_type, match=expected_message):
        obfuscator.load_key_from_file()

