"""
Buffer utils
"""

from collections import deque


class ChunkRecvBuffer:
    """
    ChunkRecvBuffer is a utility to buffer a limited number of chunks which can
    not be used immediately.
    """

    def __init__(self, maxlen=None):
        self.deque = deque([], maxlen)
        self.maxlen = maxlen

    def put(self, start_byte, data):
        """
        Adds a chunk to the buffer. If the buffer already contains the maximum
        number of chunks, the chunk with the highest start_byte is replaced with
        the new chunk.
        """

        # replace last item if the deque is full
        if self.maxlen > 0 and len(self.deque) >= self.maxlen:
            self.deque.pop()

        i = 0
        for item in self.deque:
            if item[0] > start_byte:
                break
            i += 1
        self.deque.insert(i, (start_byte, data))

    def max_available(self, available):
        """
        Calculates the max available byte position from a given start position
        when considering all chunks in the buffer.
        """
        matching_chunks = 0
        for item in self.deque:
            if item[0] > available:
                return available, matching_chunks
            available = max(available, item[0] + len(item[1]))
            matching_chunks += 1
        return available, matching_chunks

    def min(self):
        """
        Returns the minimum required start_byte by any buffered chunk.
        If the buffer is empty, `None` is returned instead.
        """
        if not self.deque:
            return None
        return self.deque[0][0]

    def pop(self):
        """
        Removes and returns the chunk with the smallest start_byte.
        """
        return self.deque.popleft()


class ChunkSendBuffer:
    """
    ChunkSendBuffer is a utility to buffer a limited number of chunks which
    have been sent but are not yet acknowledged.
    """

    def __init__(self):
        self.deque = deque()
        self.length = 0

    def put(self, expiry_time, start_byte, data):
        """
        Adds a chunk to the buffer.
        """
        i = len(self.deque)
        for item in reversed(self.deque):
            if item[0] < expiry_time:
                break
            i -= 1
        self.deque.insert(i, (expiry_time, start_byte, data))
        self.length += 1

    def adjust(self, current_time, acked_bytes):
        """
        Adjusts the buffer to the given current time and acknowledged bytes
        position by removing chunks which are expired. Chunks of which the data
        has not yet been acknowledged are returned as a list.
        """
        expired_chunks = []
        n = len(self.deque)
        while n > 0:
            item = self.deque[0]
            # check if chunk bytes have been acknowledged
            if item[1]+len(item[2]) > acked_bytes:
                # not acknowledged, check if chunk is expired
                if item[0] > current_time:
                    # not expired
                    self.length = n
                    return expired_chunks
                expired_chunks.append(item)
            # remove acknowledged or expired chunks
            self.deque.popleft()
            n -= 1

        self.length = n
        return expired_chunks

    def min_expiry_time(self):
        """
        Returns the minimum expiry time in the buffer, which is the expiry time
        for the first item. If the buffer is empty, `None` is returned instead.
        """
        if not self.deque:
            return None
        return self.deque[0][0]
