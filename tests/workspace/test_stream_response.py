import asyncio

import anyio
import pytest
from starlette.requests import ClientDisconnect

from argus.workspace.web.streamResponse import ClosingStreamingResponse


ASGI_SCOPE = {"type": "http", "asgi": {"spec_version": "2.4"}}


async def _receive():
    await anyio.sleep_forever()


@pytest.mark.parametrize("termination, error", [
    ("complete", None),
    ("send_failure", ClientDisconnect),
    ("cancelled", asyncio.CancelledError),
])
def test_closing_stream_response_closes_body(termination, error):
    chunks = []
    closed = []

    async def body():
        try:
            yield b"first"
            yield b"second"
        finally:
            await anyio.lowlevel.checkpoint()
            closed.append(True)

    async def run():
        response = ClosingStreamingResponse(body())
        with anyio.CancelScope() as request:
            async def send(message):
                if message["type"] != "http.response.body":
                    return
                chunks.append(message["body"])
                if termination == "send_failure":
                    raise OSError("fixture disconnect")
                if termination == "cancelled":
                    request.cancel()
                    await anyio.sleep_forever()

            if error is None:
                await response(ASGI_SCOPE, _receive, send)
            else:
                with pytest.raises(error):
                    await response(ASGI_SCOPE, _receive, send)

    asyncio.run(run())
    assert chunks == ([b"first", b"second", b""] if termination == "complete" else [b"first"])
    assert closed == [True]


def test_cleanup_failure_preserves_original_disconnect():
    disconnect = ClientDisconnect("fixture disconnect")
    attempts = []

    class FailingBody:
        def __aiter__(self):
            return self

        async def __anext__(self):
            return b"chunk"

        async def aclose(self):
            attempts.append(True)
            raise RuntimeError("fixture cleanup error")

    async def run():
        async def send(message):
            if message["type"] == "http.response.body":
                raise disconnect

        with pytest.raises(ClientDisconnect) as raised:
            await ClosingStreamingResponse(FailingBody())(ASGI_SCOPE, _receive, send)
        assert raised.value is disconnect

    asyncio.run(run())
    assert attempts == [True]
