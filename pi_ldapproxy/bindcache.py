from twisted.internet import reactor
from twisted.python import log

class BindCache(set):
    def __init__(self, timeout=5):
        set.__init__(self)
        self.timeout = timeout

    def add_to_cache(self, dn, password):
        item = (dn, password)
        if item not in self:
            log.msg('Adding to cache: {!r}'.format(item))
            self.add(item)
            reactor.callLater(self.timeout, self.remove_from_cache, item)
        else:
            log.msg('Already in the cache: {!r}'.format(item))

    def remove_from_cache(self, item):
        self.remove(item)
        log.msg('Removed from cache: {!r} (new: {!r})'.format(item, self))