from twisted.internet import reactor
from twisted.logger import Logger

log = Logger()

class BindCache(object):
    """
    A "bind cache" can be used to cache successful bind credentials for a predefined timeframe. This might be useful
    if applications issue multiple bind requests using the same credentials in a short timeframe.
    Obviously, using a bind cache has serious security implications: An eavesdropper could just reuse
    credentials.

    .. todo:: Consider the following scenario: Credentials are added to the bind cache, but ``reactor.callLater``
        does not fire for some reason. Right now, the credentials can then never be added to the bind cache again.
        Is this wanted behavior?
    """
    # Only indirectly calling reactor.callLater here to enable efficient unit testing
    # (see http://twistedmatrix.com/documents/current/core/howto/trial.html)
    callLater = reactor.callLater

    def __init__(self, timeout=5):
        """
        :param timeout: Number of seconds after which the entry is removed from the bind cache
        """
        self.timeout = timeout
        #: Map of tuples (dn, password) to insertion timestamps (determined using ``reactor.seconds``)
        self._cache = {}

    def add_to_cache(self, dn, password):
        """
        Add the credentials to the bind cache. They are automatically removed from the cache after ``self.timeout``
        seconds using the ``reactor.callLater`` mechanism.
        If the credentials are already found in the bind cache, the time until their removal is **not** extended!
        :param dn: user distinguished name
        :param password: user password
        """
        item = (dn, password)
        if item not in self._cache:
            current_time = reactor.seconds()
            log.info('Adding to cache: dn={dn!r}, time={time!r}', dn=dn, time=current_time)
            self._cache[item] = current_time
            self.callLater(self.timeout, self.remove_from_cache, dn, password)
        else:
            log.info('Already in the cache: dn={dn!r}', dn=dn)

    def remove_from_cache(self, dn, password):
        """
        If the given credentials are found in the cache, they are removed.
        If they cannot be found, nothing happens.
        :param dn: user distinguished name
        :param password: user password
        """
        item = (dn, password)
        if item in self._cache:
            del self._cache[item]
            log.info('Removed from cache: dn={dn!r} ({remaining!r} remaining)', dn=dn, remaining=len(self._cache))
        else:
            log.info("Removal failed as dn={dn!r} cached", dn=dn)

    def is_cached(self, dn, password):
        """
        Determines whether the given credentials are found in the bind cache.
        :param dn: user distinguished name
        :param password: user password
        :return: a boolean
        """
        item = (dn, password)
        if item in self._cache:
            current_time = reactor.seconds()
            inserted_time = self._cache[item]
            # Even though credentials **should** be removed automatically by ``callLater``, check
            # the stored timestamp.
            if current_time - inserted_time < self.timeout:
                return True
            else:
                log.info('Inconsistent bind cache: dn={dn!r}, inserted={inserted!r}, current={current!r}',
                    dn=dn, inserted=inserted_time, current=current_time,
                )
        return False
