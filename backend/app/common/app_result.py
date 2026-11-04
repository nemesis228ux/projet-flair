from typing import Generic, TypeVar, cast

D = TypeVar("D")
E = TypeVar("E")
_MISSING = object()


class GenericAppResult(Generic[D, E]):
    def __init__(
        self,
        ok: bool,
        data: D | object = _MISSING,
        error: E | object = _MISSING,
    ) -> None:
        if ok and data is _MISSING:
            raise ValueError("A successful result must contain data.")
        if not ok and error is _MISSING:
            raise ValueError("A failed result must contain an error.")

        self._ok = ok
        self._data = data
        self._error = error

    def is_success(self) -> bool:
        return self._ok

    def is_error(self) -> bool:
        return not self._ok

    @property
    def data(self) -> D:
        if self.is_error():
            raise RuntimeError("Cannot access data on a failed result.")
        return cast(D, self._data)

    @property
    def error(self) -> E:
        if self.is_success():
            raise RuntimeError("Cannot access error on a successful result.")
        return cast(E, self._error)

    @classmethod
    def success(cls, data: D) -> "GenericAppResult[D, E]":
        return cls(ok=True, data=data)

    @classmethod
    def failure(cls, error: E) -> "GenericAppResult[D, E]":
        return cls(ok=False, error=error)

    def __repr__(self) -> str:
        if self.is_success():
            return f"GenericAppResult(Status=SUCCESS, Data={self._data!r})"
        return f"GenericAppResult(Status=FAILURE, Error={self._error!r})"
