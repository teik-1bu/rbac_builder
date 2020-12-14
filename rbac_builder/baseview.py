import re

from .const import PERMISSION_PREFIX


class BaseView(object):
    rbac_builder = None
    base_permissions = None
    class_permission_name = None
    previous_class_permission_name = None
    method_permission_name = None
    previous_method_permission_name = None
    actions = None

    def __init__(self):
        # Init class permission override attrs
        if not self.previous_class_permission_name and self.class_permission_name:
            self.previous_class_permission_name = self.__class__.__name__
        self.class_permission_name = (
                self.class_permission_name or self.__class__.__name__
        )

        # Init previous permission override attrs
        is_collect_previous = False
        if not self.previous_method_permission_name and self.method_permission_name:
            self.previous_method_permission_name = dict()
            is_collect_previous = True
        self.method_permission_name = self.method_permission_name or dict()

        # Collect base_permissions and infer previous permissions
        is_add_base_permissions = False
        if self.base_permissions is None:
            self.base_permissions = set()
            is_add_base_permissions = True

        for attr_name in dir(self):
            if hasattr(getattr(self, attr_name), "_permission_name"):
                if is_collect_previous:
                    self.previous_method_permission_name[attr_name] = getattr(
                        getattr(self, attr_name), "_permission_name"
                    )
                _permission_name = self.get_method_permission(attr_name)
                if is_add_base_permissions:
                    self.base_permissions.add(PERMISSION_PREFIX + _permission_name)

        self.base_permissions = list(self.base_permissions)

    def get_method_permission(self, method_name: str) -> str:
        """
            Returns the permission name for a method
        """
        permission = self.method_permission_name.get(method_name)
        if permission:
            return permission
        else:
            return getattr(getattr(self, method_name), "_permission_name")

    @staticmethod
    def _prettify_name(name):
        """
            Prettify pythonic variable name.

            For example, 'HelloWorld' will be converted to 'Hello World'

            :param name:
                Name to prettify.
        """
        return re.sub(r"(?<=.)([A-Z])", r" \1", name)

    @staticmethod
    def _prettify_column(name):
        """
            Prettify pythonic variable name.

            For example, 'hello_world' will be converted to 'Hello World'

            :param name:
                Name to prettify.
        """
        return re.sub("[._]", " ", name).title()
