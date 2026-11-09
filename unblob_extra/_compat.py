"""Compatibility with the two unblob encrypted-chunk report interfaces.

unblob 26.6.4 uses ValidChunk(is_encrypted=bool), whereas the current
upstream development branch stores EncryptionMetadataReport objects.
"""

from unblob.models import ValidChunk

try:
    from unblob.report import EncryptionMetadataReport
except ImportError:  # released unblob 26.6.4
    EncryptionMetadataReport = None


def create_valid_chunk(*, start_offset: int, end_offset: int, encrypted: bool):
    """Create a chunk using the installed unblob version's encryption API."""
    if EncryptionMetadataReport is None:
        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
            is_encrypted=encrypted,
        )
    return ValidChunk(
        start_offset=start_offset,
        end_offset=end_offset,
        metadata_reports=[EncryptionMetadataReport(is_encrypted=True)]
        if encrypted
        else [],
    )
