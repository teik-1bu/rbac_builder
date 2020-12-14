from sqlalchemy import Column, ForeignKey, UniqueConstraint
from sqlalchemy import (
    String
)
from sqlalchemy.orm import relationship, backref

from rbac_builder.models import Model
from rbac_builder.utils import generate_uuid


class PermissionView(Model):
    __tablename__ = "permission_view"
    __table_args__ = (UniqueConstraint("permission_id", "view_menu_id"),)
    id = Column(String(36), primary_key=True, default=generate_uuid)
    permission_id = Column(String(36), ForeignKey("permission.id", ondelete='CASCADE'))
    permission = relationship("Permission", backref=backref('permission', passive_deletes=True))
    view_menu_id = Column(String(36), ForeignKey("view_menu.id", ondelete='CASCADE'))
    view_menu = relationship("ViewMenu", backref=backref('view_menu', passive_deletes=True))

    def __repr__(self):
        return str(self.permission).replace("_", " ") + " on " + str(self.view_menu)
