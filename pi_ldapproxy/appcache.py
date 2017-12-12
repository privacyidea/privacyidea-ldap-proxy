import functools

from twisted.internet import reactor
from twisted.logger import Logger

log = Logger()

def case_insensitive_dn(wrapped_function):
    """
    This decorator is used in the ``AppCache`` class to implement case-insensitive DN storage.
    :param wrapped_function: A function accepting ``dn`` as first argument
    :return: Wrapper function which converts the DN to lowercase before passing it to ``wrapped_function``
    """
    @functools.wraps(wrapped_function)
    def dn_wrapper(self, dn, *args, **kwargs):
        if self.case_insensitive:
            dn = dn.lower()
        return wrapped_function(self, dn, *args, **kwargs)
    return dn_wrapper


class AppCache(object):
    """
    The app cache stores the association of a DN with a so-called "app marker" for a specific timeframe.
    """
    # (see http://twistedmatrix.com/documents/current/core/howto/trial.html)
    callLater = reactor.callLater

    def __init__(self, timeout, case_insensitive=False):
        """
        :param timeout: The association is kept in the cache for this timeframe
        :param case_insensitive: Convert DNs to lower case before storing them
        """
        self.timeout = timeout
        self.case_insensitive = case_insensitive

        #: Map of dn to tuples (app marker, insertion timestamp)
        self._entries = {}

    @case_insensitive_dn
    def add_to_cache(self, dn, marker):
        """
        Add the entry to the app cache. It will be automatically removed after ``timeout`` seconds.
        If an entry for ``dn`` (with any marker) already exists, it will be overwritten.
        Keep in mind that removal will then provoke a "Removal from app
        cache failed: ... mapped to ... " log message!
        If an entry for ``dn`` with the same marker exists, the eviction timeout will *not*
        be extended if it is added again.
        This function respects the ``case_insensitive`` option.
        :param dn: DN
        :param marker: App marker (a string)
        """
        if dn in self._entries:
            log.info('Entry {dn!r} already cached {marker!r}, overwriting ...',
                     dn=dn, marker=self._entries[dn])
        current_time = reactor.seconds()
        log.info('Adding to app cache: dn={dn!r}, marker={marker!r}, time={time!r}',
                 dn=dn, time=current_time, marker=marker)
        self._entries[dn] = (marker, current_time)
        self.callLater(self.timeout, self.remove_from_cache, dn, marker)

    @case_insensitive_dn
    def remove_from_cache(self, dn, marker):
        """
        Remove the entry from the app cache. If the DN is mapped to a different marker, a warning is emitted
        and the entry is *not* removed! If the entry does not exist in the app cache, a message is
        written to the log.
        This function respects the ``case_insensitive`` option.
        :param dn: DN
        :param marker: App marker (a string)
        """
        if dn in self._entries:
            stored_marker, stored_timestamp = self._entries[dn]
            if stored_marker == marker:
                del self._entries[dn]
                log.info('Removed {dn!r}/{marker!r} from app cache', dn=dn, marker=marker)
            else:
                log.warn('Removal from app cache failed: {dn!r} mapped to {stored!r}, not {marker!r}',
                         dn=dn, stored=stored_marker, marker=marker)
        else:
            log.info('Removal from app cache failed, as dn={dn!r} is not cached', dn=dn)

    @case_insensitive_dn
    def get_cached_marker(self, dn):
        """
        Retrieve the cached marker for the distinguished name ``dn``. This actually checks that the stored entry
        is still valid. If ``dn`` is not found in the cache, ``None`` is returned and a message is written to the log.
        This function respects the ``case_insensitive`` option.
        :param dn: DN
        :return: string or None
        """
        if dn in self._entries:
            marker, timestamp = self._entries[dn]
            current_time = reactor.seconds()
            if current_time - timestamp < self.timeout:
                return marker
            else:
                log.warn('Inconsistent app cache: dn={dn!r}, inserted={inserted!r}, current={current!r}',
                    dn=dn, inserted=timestamp, current=current_time
                )
        else:
            log.info('No entry in app cache for dn={dn!r}', dn=dn)
        return None
