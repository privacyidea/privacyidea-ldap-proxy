from twisted.internet import reactor
from twisted.logger import Logger

log = Logger()

class PreambleCache(object):
    # (see http://twistedmatrix.com/documents/current/core/howto/trial.html)
    callLater = reactor.callLater

    def __init__(self, timeout):
        self.timeout = timeout

        #: Map of dn to tuples (app marker, insertion timestamp)
        self._preambles = {}

    def add_to_cache(self, dn, marker):
        if dn in self._preambles:
            log.info('Entry {dn!r} already cached (marker={marker!r}), overwriting ...'.format(dn=dn, marker=marker))
        current_time = reactor.seconds()
        log.info('Adding to preamble cache: dn={dn!r}, marker={marker!r}, time={time!r}',
                 dn=dn, time=current_time, marker=marker)
        self._preambles[dn] = (marker, current_time)
        self.callLater(self.timeout, self.remove_from_cache, dn, marker)

    def remove_from_cache(self, dn, marker):
        if dn in self._preambles:
            stored_marker, stored_timestamp = self._preambles[dn]
            if stored_marker == marker:
                del self._preambles[dn]
                log.info('Removed {!r}/{!r} from preamble cache'.format(dn, marker))
            else:
                log.warn('Removal from preamble cache failed: {!r} mapped to {!r}, not {!r}'.format(
                    dn, stored_marker, marker
                ))
        else:
            log.info('Removal from preamble cache failed, as dn={!r} is not cached'.format(dn))

    def get_cached_marker(self, dn):
        if dn in self._preambles:
            marker, timestamp = self._preambles[dn]
            current_time = reactor.seconds()
            if current_time - timestamp < self.timeout:
                return marker
            else:
                log.warn('Inconsistent preamble cache: dn={dn!r}, inserted={inserted!r}, current={current!r}'.format(
                    dn=dn, inserted=timestamp, current=current_time
                ))
        else:
            log.info('No entry in preamble cache for dn={dn!r}'.format(dn=dn))
        return None
