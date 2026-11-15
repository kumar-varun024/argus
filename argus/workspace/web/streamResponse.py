"""Close chat generators when a response consumer disconnects between chunks."""

import anyio
from starlette.responses import StreamingResponse


class ClosingStreamingResponse(StreamingResponse):
    async def __call__(self, scope, receive, send):
        response_failed = False
        try:
            await super().__call__(scope, receive, send)
        except BaseException:
            response_failed = True
            raise
        finally:
            close = getattr(self.body_iterator, "aclose", None)
            if close is not None:
                try:
                    # Disconnect cancellation must not interrupt provider teardown
                    # and turn persistence. Bound cleanup for a stalled provider.
                    with anyio.move_on_after(5, shield=True):
                        await close()
                except BaseException:
                    if not response_failed:
                        raise
