from pydantic import BaseModel


class SaProposal(BaseModel):
    proposal_num: int | None = None
    encryption_alg: str | None = None
    key_length: int | None = None
    auth_alg: str | None = None
    dh_group: str | None = None
    lifetime_seconds: int | None = None


class IkeHandshake(BaseModel):
    ike_version: str | None = None
    exchange_type: str | None = None
    initiator_spi: str | None = None
    responder_spi: str | None = None
    proposals: list[SaProposal] = []
    pfs_enabled: bool | None = None
    vendor_ids: list[str] = []
    implementation_guess: str | None = None

    @property
    def chosen_proposal(self) -> SaProposal | None:
        return self.proposals[0] if self.proposals else None
