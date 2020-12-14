from sqlalchemy import Column
from sqlalchemy import (
    String
)

from rbac_builder.models import Model
from rbac_builder.utils import generate_uuid


class ViewMenu(Model):
    __tablename__ = "view_menu"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), unique=True, nullable=False)

    def __eq__(self, other):
        return (isinstance(other, self.__class__)) and (self.name == other.name)

    def __neq__(self, other):
        return self.name != other.name

    def __repr__(self):
        return self.name
