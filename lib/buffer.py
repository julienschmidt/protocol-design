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

