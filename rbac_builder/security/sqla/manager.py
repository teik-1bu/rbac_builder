import logging
from typing import List, Optional

from sqlalchemy import and_, literal
from sqlalchemy.engine.reflection import Inspector

from rbac_builder import const as c
from rbac_builder.models import Base
from .models import PermissionView, Permission, ViewMenu, Role, assoc_permissionview_role
from ..manager import BaseSecurityManager

log = logging.getLogger(__name__)


class SecurityManager(BaseSecurityManager):
    """
        Responsible for authentication, registering security views,
        role and permission auto management

        If you want to change anything just inherit and override, then
        pass your own security manager to AppBuilder.
    """

    role_model = Role
    permission_model = Permission
    viewmenu_model = ViewMenu
    permissionview_model = PermissionView

    def __init__(self, rbac_builder):
        super(SecurityManager, self).__init__(rbac_builder)
        self.create_db()

    @property
    def get_session(self):
        return self.rbac_builder.get_session

    def create_db(self):
        try:
            engine = self.get_session.get_bind(mapper=None, clause=None)
            inspector = Inspector.from_engine(engine)
            if "permission" not in inspector.get_table_names():
                log.info(c.LOGMSG_INF_SEC_NO_DB)
                Base.metadata.create_all(engine)
                log.info(c.LOGMSG_INF_SEC_ADD_DB)
            super(SecurityManager, self).create_db()
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_CREATE_DB.format(str(e)))
            exit(1)

    """
    -----------------------
     PERMISSION MANAGEMENT
    -----------------------
    """
    """
    ----------------------
     PRIMITIVES FOR ROLES
    ----------------------
    """

    def add_role(self, name: str) -> Optional[Role]:
        role = self.find_role(name)
        if role is None:
            try:
                role = self.role_model()
                role.name = name
                self.get_session.add(role)
                self.get_session.commit()
                log.info(c.LOGMSG_INF_SEC_ADD_ROLE.format(name))
                return role
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_ADD_ROLE.format(str(e)))
                self.get_session.rollback()
        return role

    def update_role(self, pk, name: str) -> Optional[Role]:
        role = self.get_session.query(self.role_model).get(pk)
        if not role:
            return
        try:
            role.name = name
            self.get_session.merge(role)
            self.get_session.commit()
            log.info(c.LOGMSG_INF_SEC_UPD_ROLE.format(role))
            return role
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_UPD_ROLE.format(str(e)))
            self.get_session.rollback()
            return

    def find_role(self, name):
        return self.get_session.query(self.role_model).filter_by(name=name).first()

    def find_role_by_id(self, pk):
        return self.get_session.query(self.role_model).filter_by(id=pk).first()

    def get_all_roles(self):
        return self.get_session.query(self.role_model).all()

    def del_role(self, pk):
        role = self.get_session.query(self.role_model).get(pk)
        if not role or role.name == "Super Admin" or role.name == "Public":
            return False
        try:
            self.get_session.delete(role)
            self.get_session.commit()
            log.info(c.LOGMSG_INF_SEC_UPD_ROLE.format(role))
            return True
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_UPD_ROLE.format(str(e)))
            self.get_session.rollback()
            return False

    """
    ----------------------------
     PRIMITIVES FOR PERMISSIONS
    ----------------------------
    """

    def get_public_role(self):
        return (
            self.get_session.query(self.role_model)
                .filter_by(name=self.auth_role_public)
                .first()
        )

    def get_public_permissions(self):
        role = self.get_public_role()
        if role:
            return role.permissions
        return []

    def find_permission(self, name):
        """
            Finds and returns a Permission by name
        """
        return (
            self.get_session.query(self.permission_model).filter_by(name=name).first()
        )

    def find_roles_permission_view_menus(self, permission_name: str, role_ids: List[int]):
        return (
            self.rbac_builder.get_session.query(self.permissionview_model)
                .join(
                assoc_permissionview_role,
                and_(
                    (self.permissionview_model.id ==
                     assoc_permissionview_role.c.permission_view_id),
                ),
            )
                .join(self.role_model)
                .join(self.permission_model)
                .join(self.viewmenu_model)
                .filter(
                self.permission_model.name == permission_name,
                self.role_model.id.in_(role_ids))
        ).all()

    def find_permission_view_by_roles(
            self,
            role_ids: List[int],
            no_menu=True
    ):
        return (
            self.rbac_builder.get_session.query(self.permissionview_model)
                .join(
                assoc_permissionview_role,
                and_(
                    (self.permissionview_model.id ==
                     assoc_permissionview_role.c.permission_view_id),
                ),
            )
                .join(self.role_model)
                .join(self.permission_model)
                .join(self.viewmenu_model)
                .filter(
                self.permission_model.name != 'menu_access' if no_menu else self.permission_model.name is not None,
                self.role_model.id.in_(role_ids))
        ).all()

    def exist_permission_on_roles(
            self,
            view_name: str,
            permission_name: str,
            role_ids: List[int],
    ) -> bool:
        """
            Method to efficiently check if a certain permission exists
            on a list of role id's. This is used by `has_access`

        :param view_name: The views's name to check if exists on one of the roles
        :param permission_name: The permission name to check if exists
        :param role_ids: a list of Role ids
        :return: Boolean
        """
        q = (
            self.rbac_builder.get_session.query(self.permissionview_model)
                .join(
                assoc_permissionview_role,
                and_(
                    (self.permissionview_model.id ==
                     assoc_permissionview_role.c.permission_view_id),
                ),
            )
                .join(self.role_model)
                .join(self.permission_model)
                .join(self.viewmenu_model)
                .filter(
                self.viewmenu_model.name == view_name,
                self.permission_model.name == permission_name,
                self.role_model.id.in_(role_ids),
            )
                .exists()
        )
        # Special case for MSSQL/Oracle (works on PG and MySQL > 8)
        if self.rbac_builder.get_session.bind.dialect.name in ("mssql", "oracle"):
            return self.rbac_builder.get_session.query(literal(True)).filter(q).scalar()
        return self.rbac_builder.get_session.query(q).scalar()

    def add_permission(self, name):
        """
            Adds a permission to the backend, models permission

            :param name:
                name of the permission: 'can_add','can_edit' etc...
        """
        perm = self.find_permission(name)
        if perm is None:
            try:
                perm = self.permission_model()
                perm.name = name
                self.get_session.add(perm)
                self.get_session.commit()
                return perm
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_ADD_PERMISSION.format(str(e)))
                self.get_session.rollback()
        return perm

    def del_permission(self, name: str) -> bool:
        """
            Deletes a permission from the backend, models permission

            :param name:
                name of the permission: 'can_add','can_edit' etc...
        """
        perm = self.find_permission(name)
        if not perm:
            log.warning(c.LOGMSG_WAR_SEC_DEL_PERMISSION.format(name))
            return False
        try:
            pvms = self.get_session.query(self.permissionview_model).filter(
                self.permissionview_model.permission == perm
            ).all()
            if pvms:
                log.warning(c.LOGMSG_WAR_SEC_DEL_PERM_PVM.format(perm, pvms))
                return False
            self.get_session.delete(perm)
            self.get_session.commit()
            return True
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_DEL_PERMISSION.format(str(e)))
            self.get_session.rollback()
            return False

    """
    ----------------------
     PRIMITIVES VIEW MENU
    ----------------------
    """

    def find_view_menu(self, name):
        """
            Finds and returns a ViewMenu by name
        """
        return self.get_session.query(self.viewmenu_model).filter_by(name=name).first()

    def get_all_view_menu(self):
        return self.get_session.query(self.viewmenu_model).all()

    def add_view_menu(self, name):
        """
            Adds a views or menu to the backend, models view_menu
            param name:
                name of the views menu to add
        """
        view_menu = self.find_view_menu(name)
        if view_menu is None:
            try:
                view_menu = self.viewmenu_model()
                view_menu.name = name
                self.get_session.add(view_menu)
                self.get_session.commit()
                return view_menu
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_ADD_VIEWMENU.format(str(e)))
                self.get_session.rollback()
        return view_menu

    def del_view_menu(self, name: str) -> bool:
        """
            Deletes a ViewMenu from the backend

            :param name:
                name of the ViewMenu
        """
        view_menu = self.find_view_menu(name)
        if not view_menu:
            log.warning(c.LOGMSG_WAR_SEC_DEL_VIEWMENU.format(name))
            return False
        try:
            pvms = self.get_session.query(self.permissionview_model).filter(
                self.permissionview_model.view_menu == view_menu
            ).all()
            if pvms:
                log.warning(c.LOGMSG_WAR_SEC_DEL_VIEWMENU_PVM.format(view_menu, pvms))
                return False
            self.get_session.delete(view_menu)
            self.get_session.commit()
            return True
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_DEL_PERMISSION.format(str(e)))
            self.get_session.rollback()
            return False

    """
    ----------------------
     PERMISSION VIEW MENU
    ----------------------
    """

    def find_permission_view_menu(self, permission_name, view_menu_name):
        """
            Finds and returns a PermissionView by names
        """
        permission = self.find_permission(permission_name)
        view_menu = self.find_view_menu(view_menu_name)
        if permission and view_menu:
            return (
                self.get_session.query(self.permissionview_model)
                    .filter_by(permission=permission, view_menu=view_menu)
                    .first()
            )

    def find_permission_view_menu_by_id(self, pk):
        return (
            self.get_session.query(self.permissionview_model)
                .filter_by(id=pk)
                .first()
        )

    def find_permissions_view_menu(self, view_menu):
        """
            Finds all permissions from ViewMenu, returns list of PermissionView

            :param view_menu: ViewMenu object
            :return: list of PermissionView objects
        """
        return (
            self.get_session.query(self.permissionview_model)
                .filter_by(view_menu_id=view_menu.id)
                .all()
        )

    def add_permission_view_menu(self, permission_name, view_menu_name):
        """
            Adds a permission on a views or menu to the backend

            :param permission_name:
                name of the permission to add: 'can_add','can_edit' etc...
            :param view_menu_name:
                name of the views menu to add
        """
        if not (permission_name and view_menu_name):
            return None
        pv = self.find_permission_view_menu(
            permission_name,
            view_menu_name
        )
        if pv:
            return pv
        vm = self.add_view_menu(view_menu_name)
        perm = self.add_permission(permission_name)
        pv = self.permissionview_model()
        pv.view_menu_id, pv.permission_id = vm.id, perm.id
        try:
            self.get_session.add(pv)
            self.get_session.commit()
            log.info(c.LOGMSG_INF_SEC_ADD_PERMVIEW.format(str(pv)))
            return pv
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_ADD_PERMVIEW.format(str(e)))
            self.get_session.rollback()

    def del_permission_view_menu(self, permission_name, view_menu_name, cascade=True):
        if not (permission_name and view_menu_name):
            return
        pv = self.find_permission_view_menu(permission_name, view_menu_name)
        if not pv:
            return
        roles_pvs = self.get_session.query(self.role_model).filter(
            self.role_model.permissions.contains(pv)
        ).first()
        if roles_pvs:
            log.warning(
                c.LOGMSG_WAR_SEC_DEL_PERMVIEW.format(
                    view_menu_name, permission_name, roles_pvs
                )
            )
            return
        try:
            # delete permission on views
            self.get_session.delete(pv)
            self.get_session.commit()
            # if no more permission on permission views, delete permission
            if not cascade:
                return
            if (
                    not self.get_session.query(self.permissionview_model)
                            .filter_by(permission=pv.permission)
                            .all()
            ):
                self.del_permission(pv.permission.name)
            log.info(
                c.LOGMSG_INF_SEC_DEL_PERMVIEW.format(permission_name, view_menu_name)
            )
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_DEL_PERMVIEW.format(str(e)))
            self.get_session.rollback()

    def exist_permission_on_views(self, lst, item):
        for i in lst:
            if i.permission and i.permission.name == item:
                return True
        return False

    def exist_permission_on_view(self, lst, permission, view_menu):
        for i in lst:
            if i.permission.name == permission and i.view_menu.name == view_menu:
                return True
        return False

    def add_permission_role(self, role, perm_view):
        """
            Add permission-ViewMenu object to Role

            :param role:
                The role object
            :param perm_view:
                The PermissionViewMenu object
        """
        if perm_view and perm_view not in role.permissions:
            try:
                role.permissions.append(perm_view)
                self.get_session.merge(role)
                self.get_session.commit()
                log.info(
                    c.LOGMSG_INF_SEC_ADD_PERMROLE.format(str(perm_view), role.name)
                )
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_ADD_PERMROLE.format(str(e)))
                self.get_session.rollback()

    def del_permission_role(self, role, perm_view):
        """
            Remove permission-ViewMenu object to Role

            :param role:
                The role object
            :param perm_view:
                The PermissionViewMenu object
        """
        if perm_view in role.permissions:
            try:
                role.permissions.remove(perm_view)
                self.get_session.merge(role)
                self.get_session.commit()
                log.info(
                    c.LOGMSG_INF_SEC_DEL_PERMROLE.format(str(perm_view), role.name)
                )
            except Exception as e:
                log.error(c.LOGMSG_ERR_SEC_DEL_PERMROLE.format(str(e)))
                self.get_session.rollback()

    def update_permissions_role(self, role, perm_views):
        try:
            role.permissions = perm_views
            self.get_session.merge(role)
            self.get_session.commit()
        except Exception as e:
            log.error(c.LOGMSG_ERR_SEC_ADD_PERMROLE.format(str(e)))
            self.get_session.rollback()