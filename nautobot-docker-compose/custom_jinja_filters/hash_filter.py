import hashlib
from django_jinja import library

@library.filter
def hash(value, algorithm="sha1"):
    """
    Mimic Ansible's 'hash' filter.
    Usage: {{ 'test string' | hash('sha256') }}
    """
    if not isinstance(value, str):
        value = str(value)

    try:
        hash_func = getattr(hashlib, algorithm.lower())
    except AttributeError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    return hash_func(value.encode("utf-8")).hexdigest()
