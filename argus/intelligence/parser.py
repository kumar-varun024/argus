import re

from .models import APIEndpoint

CRUD = {
    "GET": "READ",
    "POST": "CREATE",
    "PUT": "UPDATE",
    "PATCH": "UPDATE",
    "DELETE": "DELETE",
}


class APIParser:

    def parse(self, method: str, path: str):

        method = method.upper()

        operation = CRUD.get(method, "UNKNOWN")

        resource = self._resource(path)

        return APIEndpoint(
            method=method,
            path=path,
            resource=resource,
            operation=operation,
            object_identifier=self._has_identifier(path),
            business_object=resource.title(),
        )

    def _resource(self, path):

        parts = [p for p in path.split("/") if p]

        for part in parts:

            if part.startswith("v"):

                continue

            if part == "api":

                continue

            return part

        return "unknown"

    def _has_identifier(self, path):

        return bool(
            re.search(
                r"/([0-9]+|[a-f0-9]{24}|[a-f0-9-]{36})",
                path,
                re.I,
            )
        )
