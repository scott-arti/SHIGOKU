from dataclasses import dataclass


@dataclass
class FuzzResult:
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str = ""
    redirect_location: str = ""
