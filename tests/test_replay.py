from auth.kerberos.replay_cache import ReplayCache


def test_first_authenticator_is_accepted():
    cache = ReplayCache()
    assert cache.contains("lucas", 1) is False
    cache.add("lucas", 1)
    assert cache.contains("lucas", 1) is True


def test_same_authenticator_is_rejected_twice():
    cache = ReplayCache()
    cache.add("lucas", 1)
    assert cache.contains("lucas", 1) is True


def test_new_authenticator_is_accepted():
    cache = ReplayCache()
    cache.add("lucas", 1)
    assert cache.contains("lucas", 2) is False


def test_old_entries_can_be_removed():
    cache = ReplayCache()
    cache.add("lucas", 1)
    cache.add("alice", 2)
    assert cache.contains("lucas", 1) is True
    cache.remove("lucas", 1)
    assert cache.contains("lucas", 1) is False
