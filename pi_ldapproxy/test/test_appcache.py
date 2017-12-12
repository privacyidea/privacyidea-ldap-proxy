import time
import twisted
from twisted.internet import task

from pi_ldapproxy.appcache import AppCache

DN1 = 'cn=test,cn=users,dc=test,dc=intranet'
DN1_OTHERCASE = 'cn=test,cn=Users,dc=test,DC=IntraNET'
DN2 = 'cn=other,cn=users,dc=test,dc=intranet'
DN3 = 'cn=someone,cn=users,dc=test,dc=intranet'
MARKER1 = 'marker1'
MARKER2 = 'marker2'
TIMEOUT = 5

class TestAppCache(twisted.trial.unittest.TestCase):
    def test_multiple_entries(self):
        cache = AppCache(TIMEOUT)
        clock = task.Clock()
        cache.callLater = clock.callLater
        cache.add_to_cache(DN1, MARKER1)
        cache.add_to_cache(DN1, MARKER2)
        cache.add_to_cache(DN2, MARKER1)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER2) # is overwritten!
        self.assertEqual(cache.get_cached_marker(DN1_OTHERCASE), None)
        self.assertEqual(cache.get_cached_marker(DN2), MARKER1)
        self.assertEqual(cache.get_cached_marker(DN3), None)

    def test_manual_removal(self):
        cache = AppCache(TIMEOUT)
        clock = task.Clock()
        cache.callLater = clock.callLater
        cache.add_to_cache(DN1, MARKER1)
        cache.add_to_cache(DN2, MARKER2)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER1)
        self.assertEqual(cache.get_cached_marker(DN2), MARKER2)
        # Remove (DN2, MARKER2)
        cache.remove_from_cache(DN2, MARKER2)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER1)
        self.assertEqual(cache.get_cached_marker(DN2), None)
        # Overwrite (DN1, MARKER1) with MARKER2
        cache.add_to_cache(DN1, MARKER2)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER2)
        # Remove (DN1, MARKER1) -- no effect.
        cache.remove_from_cache(DN1, MARKER1)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER2)
        # Remove (DN1_OTHERCASE, MAKER2) -- no effect.
        cache.remove_from_cache(DN1_OTHERCASE, MARKER2)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER2)
        # Remove (DN1, MARKER2) -- removed!
        cache.remove_from_cache(DN1, MARKER2)
        self.assertEqual(cache.get_cached_marker(DN1), None)
        self.assertEqual(cache.get_cached_marker(DN2), None)

    def test_case_insensitive(self):
        clock = task.Clock()
        cache = AppCache(2, True)
        cache.callLater = clock.callLater
        # Add and wait a second, it should still be there (also in another case)
        cache.add_to_cache(DN1, MARKER1)
        clock.advance(1)
        self.assertEqual(cache.get_cached_marker(DN1_OTHERCASE), MARKER1)
        # Wait another two seconds, it should not be there anymore
        clock.advance(2)
        self.assertEqual(cache.get_cached_marker(DN1_OTHERCASE), None)
        # Add and remove manually
        cache.add_to_cache(DN1, MARKER1)
        self.assertEqual(cache.get_cached_marker(DN1.upper()), MARKER1)
        self.assertEqual(cache.get_cached_marker(DN1_OTHERCASE.upper()), MARKER1)
        clock.advance(1)
        self.assertEqual(cache.get_cached_marker(DN1.upper()), MARKER1)
        self.assertEqual(cache.get_cached_marker(DN1_OTHERCASE.upper()), MARKER1)
        cache.remove_from_cache(DN1_OTHERCASE, MARKER1)
        self.assertEqual(cache.get_cached_marker(DN1.upper()), None)
        self.assertEqual(cache.get_cached_marker(DN1_OTHERCASE.upper()), None)

    def test_automatic_removal(self):
        clock = task.Clock()
        cache = AppCache(2)
        cache.callLater = clock.callLater
        # Add and wait a second, it should still be there
        cache.add_to_cache(DN1, MARKER1)
        clock.advance(1)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER1)
        # Wait another two seconds, it should not be there anymore
        clock.advance(2)
        self.assertEqual(cache.get_cached_marker(DN1), None)

    def test_automatic_removal_overwrite_different(self):
        clock = task.Clock()
        cache = AppCache(2)
        cache.callLater = clock.callLater
        # Add and wait a second, it should still be there
        cache.add_to_cache(DN1, MARKER1)
        clock.advance(1)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER1)
        cache.add_to_cache(DN1, MARKER2)
        # Wait a second, the new entry should still be there
        clock.advance(1)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER2)
        # Wait another two seconds, it should not be there anymore
        clock.advance(2)
        self.assertEqual(cache.get_cached_marker(DN1), None)

    def test_callLater_failure(self):
        """
        Test what happens in case ``reactor.callLater`` does not fire for some reason
        """
        cache = AppCache(1)
        cache.callLater = lambda *args, **kwargs: None
        # Add and wait half a second, it should still be there
        cache.add_to_cache(DN1, MARKER1)
        time.sleep(0.5)
        self.assertEqual(cache.get_cached_marker(DN1), MARKER1)
        # TODO: This is not perfect - find a way to test this without sleeping
        time.sleep(1)
        self.assertEqual(cache.get_cached_marker(DN1), None)