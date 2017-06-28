import unittest

import time
from twisted.internet import task

from pi_ldapproxy.bindcache import BindCache

DN = 'cn=test,cn=users,dc=test,dc=intranet'
DN_OTHER = 'cn=other,cn=users,dc=test,dc=intranet'
APP = 'app1'
APP_OTHER = 'app2'
PASSWORD = 'test'
PASSWORD_OTHER = 'foo'

class BindCacheTest(unittest.TestCase):
    def test_multiple_entries(self):
        cache = BindCache()
        clock = task.Clock()
        cache.callLater = clock.callLater
        cache.add_to_cache(DN, APP, PASSWORD)
        cache.add_to_cache(DN_OTHER, APP_OTHER, PASSWORD_OTHER)
        self.assertTrue(cache.is_cached(DN, APP, PASSWORD))
        self.assertTrue(cache.is_cached(DN_OTHER, APP_OTHER, PASSWORD_OTHER))
        self.assertFalse(cache.is_cached(DN_OTHER, APP, PASSWORD))
        self.assertFalse(cache.is_cached(DN, APP, PASSWORD_OTHER))
        self.assertFalse(cache.is_cached(DN_OTHER, APP_OTHER, PASSWORD))
        self.assertFalse(cache.is_cached(DN, APP_OTHER, PASSWORD_OTHER))

    def test_manual_removal(self):
        cache = BindCache()
        clock = task.Clock()
        cache.callLater = clock.callLater
        cache.add_to_cache(DN, APP, PASSWORD)
        cache.add_to_cache(DN_OTHER, APP_OTHER, PASSWORD_OTHER)
        self.assertTrue(cache.is_cached(DN, APP, PASSWORD))
        self.assertTrue(cache.is_cached(DN_OTHER, APP_OTHER, PASSWORD_OTHER))
        # Remove (DN, APP, PASSWORD)
        cache.remove_from_cache(DN, APP, PASSWORD)
        self.assertFalse(cache.is_cached(DN, APP, PASSWORD))
        self.assertTrue(cache.is_cached(DN_OTHER, APP_OTHER, PASSWORD_OTHER))
        # Remove (DN_OTHER, APP_OTHER, PASSWORD_OTHER)
        cache.remove_from_cache(DN_OTHER, APP_OTHER, PASSWORD_OTHER)
        self.assertFalse(cache.is_cached(DN, APP, PASSWORD))
        self.assertFalse(cache.is_cached(DN_OTHER, APP_OTHER, PASSWORD_OTHER))
        # Remove (DN_OTHER, PASSWORD_OTHER) again
        cache.remove_from_cache(DN_OTHER, APP_OTHER, PASSWORD_OTHER)
        self.assertFalse(cache.is_cached(DN, APP, PASSWORD))
        self.assertFalse(cache.is_cached(DN_OTHER, APP_OTHER, PASSWORD_OTHER))

    def test_automatic_removal(self):
        clock = task.Clock()
        cache = BindCache(2)
        cache.callLater = clock.callLater
        # Add and wait a second, it should still be there
        cache.add_to_cache(DN, APP, PASSWORD)
        clock.advance(1)
        self.assertTrue(cache.is_cached(DN, APP, PASSWORD))
        # Wait another two seconds, it should not be there anymore
        clock.advance(2)
        self.assertFalse(cache.is_cached(DN, APP, PASSWORD))

    def test_callLater_failure(self):
        """
        Test what happens in case ``reactor.callLater`` does not fire for some reason
        """
        cache = BindCache(1)
        cache.callLater = lambda *args, **kwargs: None
        # Add and wait half a second, it should still be there
        cache.add_to_cache(DN, APP, PASSWORD)
        time.sleep(0.5)
        self.assertTrue(cache.is_cached(DN, APP, PASSWORD))
        self.assertFalse(cache.is_cached(DN, APP_OTHER, PASSWORD))
        # TODO: This is not perfect - find a way to test this without sleeping
        time.sleep(1)
        self.assertFalse(cache.is_cached(DN, APP, PASSWORD))
        self.assertFalse(cache.is_cached(DN, APP_OTHER, PASSWORD))
