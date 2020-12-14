from sqlalchemy import Column, ForeignKey, UniqueConstraint
from sqlalchemy import (
    String, Table
)
from sqlalchemy.orm import relationship

from rbac_builder.models import Model
from rbac_builder.utils import generate_uuid

assoc_permissionview_role = Table(
    "permission_view_role",
    Model.metadata,
    Column("id", String(36), primary_key=True, default=generate_uuid),
    Column("permission_view_id", String(36),
           ForeignKey("permission_view.id", ondelete='CASCADE')),
    Column("role_id", String(36), ForeignKey("role.id", ondelete='CASCADE')),
    UniqueConstraint("permission_view_id", "role_id"),
)


class Role(Model):
    __tablename__ = "role"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(64), unique=True, nullable=False)
    permissions = relationship(
        "PermissionView", secondary=assoc_permissionview_role, backref="role", passive_deletes=True
    )

    def __repr__(self):
        return self.name
