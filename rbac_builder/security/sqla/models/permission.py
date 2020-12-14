from sqlalchemy import Column
from sqlalchemy import (
    String
)

from rbac_builder.models import Model
from rbac_builder.utils import generate_uuid


class Permission(Model):
    __tablename__ = "permission"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), unique=True, nullable=False)

    def __repr__(self):
        return self.name
