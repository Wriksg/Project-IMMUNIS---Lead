from immunis.contracts.models import TaintTag, Trust

POLICY_VERSION = 0

def quarantine_required(tag: TaintTag) -> bool:
    return tag.trust == Trust.untrusted
