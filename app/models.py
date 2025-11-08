from typing import Optional
from pydantic import BaseModel


class UpdateSSIDPasswordRequest(BaseModel):
    ip: str
    ssid: Optional[str] = None
    password: Optional[str] = None
    reboot: Optional[bool] = False
    model: Optional[str] = None  # Optional model hint (e.g., 'pmp_450', 'force_300', 'R195W')


class RebootRequest(BaseModel):
    ip: str
    model: Optional[str] = None  # Optional model hint (e.g., 'pmp_450', 'force_300', 'R195W')
