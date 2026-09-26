from typing import Annotated, cast

from fastapi import Depends, Header, Request

from agentgate.auth.identity import Identity
from agentgate.services.gateway import Gateway


def gateway(request: Request) -> Gateway:
    return cast(Gateway, request.app.state.gateway)


async def identity(
    service: Annotated[Gateway, Depends(gateway)],
    authorization: Annotated[str | None, Header()] = None,
) -> Identity:
    return await service.authenticate(authorization)


Service = Annotated[Gateway, Depends(gateway)]
Caller = Annotated[Identity, Depends(identity)]
