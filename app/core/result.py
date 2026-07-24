from typing import Generic, TypeVar, Union, Optional

T = TypeVar('T')  # Success type
E = TypeVar('E')  # Error type

class Result(Generic[T, E]):
    """Result monad representing either success (value) or failure (error)."""
    
    def __init__(self, is_success: bool, value: Optional[T] = None, error: Optional[E] = None) -> None:
        if is_success and error is not None:
            raise ValueError("A success result cannot have an error.")
        if not is_success and error is None:
            raise ValueError("A failure result must have an error.")
            
        self._is_success = is_success
        self._value = value
        self._error = error

    @property
    def is_success(self) -> bool:
        """True if operation succeeded."""
        return self._is_success

    @property
    def is_failure(self) -> bool:
        """True if operation failed."""
        return not self._is_success

    @property
    def value(self) -> T:
        """Get success value. Raises ValueError if this is a failure result."""
        if not self._is_success:
            raise ValueError(f"Cannot get value of a failure result. Error: {self._error}")
        return self._value

    @property
    def error(self) -> E:
        """Get error. Raises ValueError if this is a success result."""
        if self._is_success:
            raise ValueError("Cannot get error of a success result.")
        return self._error

    @classmethod
    def ok(cls, value: T = None) -> 'Result[T, E]':
        """Construct a success result."""
        return cls(is_success=True, value=value)

    @classmethod
    def fail(cls, error: E) -> 'Result[T, E]':
        """Construct a failure result."""
        return cls(is_success=False, error=error)

    def __repr__(self) -> str:
        if self._is_success:
            return f"Result.ok({self._value!r})"
        return f"Result.fail({self._error!r})"
