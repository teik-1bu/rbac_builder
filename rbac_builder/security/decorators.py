import functools
import logging

from flask_jwt_extended import verify_jwt_in_request

from ..const import (
    FLAMSG_ERR_SEC_ACCESS_DENIED,
    LOGMSG_ERR_SEC_ACCESS_DENIED,
    PERMISSION_PREFIX
)

from flask import current_app


def has_access(f):
    """
        Use this decorator to enable granular security permissions to your methods.
        Permissions will be associated to a role, and roles are associated to users.

        By default the permission's name is the methods name.
    """

    if hasattr(f, '_permission_name'):
        permission_str = f._permission_name
    else:
        permission_str = f.__name__

    def wraps(self, *args, **kwargs):
        verify_jwt_in_request()
        permission_str = "{}{}".format(PERMISSION_PREFIX, f._permission_name)
        if self.method_permission_name:
            _permission_name = self.method_permission_name.get(f.__name__)
            if _permission_name:
                permission_str = "{}{}".format(PERMISSION_PREFIX, _permission_name)
        if (permission_str in self.base_permissions and
                self.rbac_builder.sm.has_access(
                    permission_str,
                    self.class_permission_name
                )):
            return f(self, *args, **kwargs)
        else:
            logging.warning(
                LOGMSG_ERR_SEC_ACCESS_DENIED.format(
                    permission_str,
                    self.__class__.__name__
                )
            )
            response_object = {
                'message': FLAMSG_ERR_SEC_ACCESS_DENIED,
            }
            return response_object, 403

    f._permission_name = permission_str
    return functools.update_wrapper(wraps, f)


def permission_name(name):
    """
        Use this decorator to override the name of the permission.
        has_access will use the methods name has the permission name
        if you want to override this add this decorator to your methods.
        This is useful if you want to aggregate methods to permissions

        It will add '_permission_name' attribute to your method
        that will be inspected by BaseView to collect your views's
        permissions.

        Note that you should use @has_access to execute after @permission_name
        like on the following example.

        Use it like this to aggregate permissions for your methods::

            class MyModelView(ModelView):
                datamodel = SQLAInterface(MyModel)

                @has_access
                @permission_name('GeneralXPTO_Permission')
                @expose(url='/xpto')
                def xpto(self):
                    return "Your on xpto"

                @has_access
                @permission_name('GeneralXPTO_Permission')
                @expose(url='/xpto2')
                def xpto2(self):
                    return "Your on xpto2"


        :param name:
            The name of the permission to override
    """

    def wraps(f):
        f._permission_name = name
        return f

    return wraps
