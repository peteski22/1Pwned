"""Utilities for handling hashed password prefix/suffix pairs."""


class HashedPassword:
    """Represents a hashed password, typically split for security purposes (see: Have I Been Pwned Passwords API).

    Attributes:
        prefix (str): The first part of the hash.
        suffix (str): The remaining part of the hash.
    """

    def __init__(self, prefix: str, suffix: str):
        """Initializes the HashedPassword object.

        Args:
            prefix: The prefix of the hash.
            suffix: The suffix of the hash.
        """
        self.prefix: str = prefix
        self.suffix: str = suffix

    def __repr__(self) -> str:
        """Provides a clear string representation of the object."""
        return f"HashedPassword(prefix='{self.prefix}', suffix='{self.suffix}')"

    def get_full_hash(self) -> str:
        """Recombines the prefix and suffix to get the full hash."""
        return self.prefix + self.suffix
