import unittest

import time
from twisted.internet import task

from pi_ldapproxy.bindcache import BindCache

DN = 'cn=test,cn=users,dc=test,dc=intranet'
DN_OTHER = 'cn=other,cn=users,dc=test,dc=intranet'
PASSWORD = 'test'
PASSWORD_OTHER = 'foo'

class BindCacheTest(unittest.TestCase):
    def test_multiple_entries(self):
        cache = BindCache()
        cache.add_to_cache(DN, PASSWORD)
        cache.add_to_cache(DN_OTHER, PASSWORD_OTHER)
        self.assertTrue(cache.is_cached(DN, PASSWORD))
        self.assertTrue(cache.is_cached(DN_OTHER, PASSWORD_OTHER))
        self.assertFalse(cache.is_cached(DN_OTHER, PASSWORD))
        self.assertFalse(cache.is_cached(DN, PASSWORD_OTHER))

    def test_manual_removal(self):
        cache = BindCache()
        cache.add_to_cache(DN, PASSWORD)
        cache.add_to_cache(DN_OTHER, PASSWORD_OTHER)
        self.assertTrue(cache.is_cached(DN, PASSWORD))
        self.assertTrue(cache.is_cached(DN_OTHER, PASSWORD_OTHER))
        # Remove (DN, PASSWORD)
        cache.remove_from_cache(DN, PASSWORD)
        self.assertFalse(cache.is_cached(DN, PASSWORD))
        self.assertTrue(cache.is_cached(DN_OTHER, PASSWORD_OTHER))
        # Remove (DN_OTHER, PASSWORD_OTHER)
        cache.remove_from_cache(DN_OTHER, PASSWORD_OTHER)
        self.assertFalse(cache.is_cached(DN, PASSWORD))
        self.assertFalse(cache.is_cached(DN_OTHER, PASSWORD_OTHER))
        # Remove (DN_OTHER, PASSWORD_OTHER) again
        cache.remove_from_cache(DN_OTHER, PASSWORD_OTHER)
        self.assertFalse(cache.is_cached(DN, PASSWORD))
        self.assertFalse(cache.is_cached(DN_OTHER, PASSWORD_OTHER))

    def test_automatic_removal(self):
        clock = task.Clock()
        cache = BindCache(2)
        cache.callLater = clock.callLater
        # Add and wait a second, it should still be there
        cache.add_to_cache(DN, PASSWORD)
        clock.advance(1)
        self.assertTrue(cache.is_cached(DN, PASSWORD))
        # Wait another two seconds, it should not be there anymore
        clock.advance(2)
        self.assertFalse(cache.is_cached(DN, PASSWORD))

    def test_callLater_failure(self):
        """
        Test what happens in case ``reactor.callLater`` does not fire for some reason
        """
        cache = BindCache(1)
        cache.callLater = lambda *args, **kwargs: None
        # Add and wait half a second, it should still be there
        cache.add_to_cache(DN, PASSWORD)
        time.sleep(0.5)
        self.assertTrue(cache.is_cached(DN, PASSWORD))
        # TODO: This is not perfect - find a way to test this without sleeping
        time.sleep(1)
        self.assertFalse(cache.is_cached(DN, PASSWORD))