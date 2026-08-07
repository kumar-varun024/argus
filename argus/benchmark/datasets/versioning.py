class VersioningManager:
    """Handles semantic versioning and compatibility checks for datasets."""
    
    SUPPORTED_SCHEMA_VERSIONS = ["1.0"]
    
    @classmethod
    def is_compatible(cls, schema_version: str) -> bool:
        """Checks if the dataset's schema version is supported by the framework."""
        # Simple exact match for now. Could be upgraded to proper SemVer.
        return schema_version in cls.SUPPORTED_SCHEMA_VERSIONS
