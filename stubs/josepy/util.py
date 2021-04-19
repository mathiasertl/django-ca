import typing

K = typing.TypeVar('K')
V = typing.TypeVar('V')


class ImmutableMap(typing.Mapping[K, V], typing.Hashable):
    def __getitem__(self, key: K) -> V:
        ...

    def __hash__(self) -> int:
        ...

    def __iter__(self) -> typing.Iterator[K]:
        ...

    def __len__(self) -> int:
        ...
