_atomic_base_url = "https://atomicdata.dev"
_local_base_url = "http://localhost:9883"


def set_local_base_url(url: str):
    _local_base_url = url


def atomic(tail: str = "") -> str:
    if tail:
        return f"{_atomic_base_url}/{tail}"
    else:
        return _atomic_base_url


def local(tail: str = "") -> str:
    if tail:
        return f"{_local_base_url}/{tail}"
    else:
        return _local_base_url
