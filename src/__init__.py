"""Chat anonymizer package."""

def __getattr__(name):
    if name in {"AnonymizeResult", "ChatAnonymizer"}:
        from src.anonymizer import AnonymizeResult, ChatAnonymizer
        return {"AnonymizeResult": AnonymizeResult, "ChatAnonymizer": ChatAnonymizer}[name]
    raise AttributeError(name)

__all__ = ["AnonymizeResult", "ChatAnonymizer"]
