from twisted.internet import reactor
from twisted.logger import Logger

log = Logger()

class PreambleCache(object):
    """
    The preamble cache stores the association of a DN with a so-called "app marker" for a specific timeframe.
    """
    # (see http://twistedmatrix.com/documents/current/core/howto/trial.html)
    callLater = reactor.callLater

    def __init__(self, timeout):
        """
        :param timeout: The association is kept in the cache for this timeframe
        """
        self.timeout = timeout

        #: Map of dn to tuples (app marker, insertion timestamp)
        self._preambles = {}

    def add_to_cache(self, dn, marker):
        """
        Add the entry to the preamble cache. It will be automatically removed after ``timeout`` seconds.
        If an entry for ``dn`` (with any marker) already exists, it will be overwritten.
        Keep in mind that removal will then provoke a "Removal from preamble
        cache failed: ... mapped to ... " log message!
        If an entry for ``dn`` with the same marker exists, the eviction timeout will *not*
        be extended if it is added again.
        :param dn: DN
        :param marker: App marker (a string)
        """
        if dn in self._preambles:
            log.info('Entry {dn!r} already cached {marker!r}, overwriting ...',
                     dn=dn, marker=self._preambles[dn])
        current_time = reactor.seconds()
        log.info('Adding to preamble cache: dn={dn!r}, marker={marker!r}, time={time!r}',
                 dn=dn, time=current_time, marker=marker)
        self._preambles[dn] = (marker, current_time)
        self.callLater(self.timeout, self.remove_from_cache, dn, marker)

    def remove_from_cache(self, dn, marker):
        """
        Remove the entry from the preamble cache. If the DN is mapped to a different marker, a warning is emitted
        and the entry is *not* removed! If the entry does not exist in the preamble cache, a message is
        written to the log.
        :param dn: DN
        :param marker: App marker (a string)
        """
        if dn in self._preambles:
            stored_marker, stored_timestamp = self._preambles[dn]
            if stored_marker == marker:
                del self._preambles[dn]
                log.info('Removed {dn!r}/{marker!r} from preamble cache', dn=dn, marker=marker)
            else:
                log.warn('Removal from preamble cache failed: {dn!r} mapped to {stored!r}, not {marker!r}',
                         dn=dn, stored=stored_marker, marker=marker)
        else:
            log.info('Removal from preamble cache failed, as dn={dn!r} is not cached', dn=dn)

    def get_cached_marker(self, dn):
        """
        Retrieve the cached marker for the distinguished name ``dn``. This actually checks that the stored entry
        is still valid. If ``dn`` is not found in the cache, ``None`` is returned and a message is written to the log.
        :param dn: DN
        :return: string or None
        """
        if dn in self._preambles:
            marker, timestamp = self._preambles[dn]
            current_time = reactor.seconds()
            if current_time - timestamp < self.timeout:
                return marker
            else:
                log.warn('Inconsistent preamble cache: dn={dn!r}, inserted={inserted!r}, current={current!r}',
                    dn=dn, inserted=timestamp, current=current_time
                )
        else:
            log.info('No entry in preamble cache for dn={dn!r}', dn=dn)
        return None
