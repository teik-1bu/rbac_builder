import logging
from typing import List, Dict, Set

from flask_jwt_extended import current_user

from rbac_builder import const as c
from ..base_manager import BaseManager

log = logging.getLogger(__name__)


class AbstractSecurityManager(BaseManager):
    """
        Abstract SecurityManager class, declares all methods used by the
        framework.
    """

    def add_permissions_view(self, base_permissions, view_menu):
        """
            Adds a permission on a views menu to the backend

            :param base_permissions:
                list of permissions from views (all exposed methods):
                 'add','edit' etc...
            :param view_menu:
                name of the views or menu to add
        """
        raise NotImplementedError

    def add_permissions_menu(self, view_menu_name):
        """
            Adds menu_access to menu on permission_view_menu

            :param view_menu_name:
                The menu name
        """
        raise NotImplementedError

    def register_views(self):
        """
            Generic function to create the security views
        """
        raise NotImplementedError

    def is_item_public(self, permission_name, view_name):
        """
            Check if views has public permissions

            :param permission_name:
                the permission: show, edit...
            :param view_name:
                the name of the class views (child of BaseView)
        """
        raise NotImplementedError

    def has_access(self, permission_name, view_name):
        """
            Check if current user or public has access to views or menu
        """
        raise NotImplementedError

    def security_cleanup(self, base_views, menus, sides):
        raise NotImplementedError


class BaseSecurityManager(AbstractSecurityManager):

    def __init__(self, rbac_builder):
        super(BaseSecurityManager, self).__init__(rbac_builder)
        app = self.rbac_builder.get_app
        # Base Security Config
        app.config.setdefault("AUTH_ROLE_ADMIN", "Super Admin")
        app.config.setdefault("AUTH_ROLE_PUBLIC", "Public")

        # Setup Flask-Jwt-Extended
        self.jwt_manager = self.rbac_builder.get_jwt_manager

    @property
    def auth_role_admin(self):
        return self.rbac_builder.get_app.config["AUTH_ROLE_ADMIN"]

    @property
    def auth_role_public(self):
        return self.rbac_builder.get_app.config["AUTH_ROLE_PUBLIC"]

    def create_db(self):
        """
            Setups the DB, creates admin and public roles if they don't exist.
        """
        self.add_role(self.auth_role_admin)
        self.add_role(self.auth_role_public)

    def register_views(self):
        pass

    """
        ----------------------------------------
            PERMISSION ACCESS CHECK
        ----------------------------------------
    """

    def is_item_public(self, permission_name, view_name):
        """
            Check if views has public permissions

            :param permission_name:
                the permission: can_show, can_edit...
            :param view_name:
                the name of the class views (child of BaseView)
        """
        permissions = self.get_public_permissions()
        if permissions:
            for i in permissions:
                if (view_name == i.view_menu.name) and (
                        permission_name == i.permission.name
                ):
                    return True
            return False
        else:
            return False

    def _has_view_access(
            self, user, permission_name: str, view_name: str
    ) -> bool:
        roles = user.roles
        db_role_ids = list()

        for role in roles:
            db_role_ids.append(role.id)

        # Check database-stored roles
        return self.exist_permission_on_roles(
            view_name,
            permission_name,
            db_role_ids,
        )

    def _get_user_permission_view_menus(
            self,
            user,
            permission_name: str,
            view_menus_name: List[str]
    ) -> Set[str]:
        """
        Return a set of views menu names with a certain permission name
        that a user has access to. Mainly used to fetch all menu permissions
        on a single db call, will also check public permissions and builtin roles
        """
        db_role_ids = list()
        if user is None:
            # include public role
            roles = [self.get_public_role()]
        else:
            roles = user.roles

        result = set()
        for role in roles:
            db_role_ids.append(role.id)
        # Then check against database-stored roles
        pvms_names = [
            pvm.view_menu.name
            for pvm in self.find_roles_permission_view_menus(permission_name, db_role_ids)
        ]
        result.update(pvms_names)
        return result

    def _get_permission_view_menus_by_user(self, user, no_menu=True):
        """
        Return a set of views menu that a user has access to. Mainly used to fetch all menu permissions
        on a single db call, will also check public permissions and builtin roles
        """
        db_role_ids = list()
        if user is None:
            # include public role
            roles = [self.get_public_role()]
        else:
            roles = user.roles

        for role in roles:
            db_role_ids.append(role.id)
        # Then check against database-stored roles
        pvms = [
            {
                'id': pvm.id,
                'action': pvm.permission.name,
                'view': pvm.view_menu.name
            }
            for pvm in self.find_permission_view_by_roles(db_role_ids, no_menu)
        ]
        return pvms

    def has_access(self, permission_name, view_name):
        """
            Check if current user or public has access to views or menu
        """
        if current_user:
            return self._has_view_access(current_user, permission_name, view_name)
        else:
            return self.is_item_public(permission_name, view_name)

    def get_user_menu_access(self, menu_names: List[str] = None) -> Set[str]:
        if current_user:
            return self._get_user_permission_view_menus(
                current_user, "menu_access", view_menus_name=menu_names)
        else:
            return self._get_user_permission_view_menus(
                None, "menu_access", view_menus_name=menu_names)

    def get_user_permission_view(self) -> List[dict]:
        if current_user:
            return self._get_permission_view_menus_by_user(current_user)
        else:
            return self._get_permission_view_menus_by_user(None)

    def get_user_permission_view_menu(self) -> List[dict]:
        if current_user:
            return self._get_permission_view_menus_by_user(current_user, no_menu=False)
        else:
            return self._get_permission_view_menus_by_user(None, no_menu=False)

    def add_permissions_view(self, base_permissions, view_menu):
        """
            Adds a permission on a views menu to the backend

            :param base_permissions:
                list of permissions from views (all exposed methods):
                 'can_add','can_edit' etc...
            :param view_menu:
                name of the views or menu to add
        """
        view_menu_db = self.add_view_menu(view_menu)
        perm_views = self.find_permissions_view_menu(view_menu_db)

        if not perm_views:
            # No permissions yet on this views
            for permission in base_permissions:
                pv = self.add_permission_view_menu(permission, view_menu)
                role_admin = self.find_role(self.auth_role_admin)
                self.add_permission_role(role_admin, pv)
        else:
            # Permissions on this views exist but....
            role_admin = self.find_role(self.auth_role_admin)
            for permission in base_permissions:
                # Check if base views permissions exist
                if not self.exist_permission_on_views(perm_views, permission):
                    pv = self.add_permission_view_menu(permission, view_menu)
                    self.add_permission_role(role_admin, pv)
            for perm_view in perm_views:
                if perm_view.permission is None:
                    # Skip this perm_view, it has a null permission
                    continue
                if perm_view.permission.name not in base_permissions:
                    # perm to delete
                    roles = self.get_all_roles()
                    perm = self.find_permission(perm_view.permission.name)
                    # del permission from all roles
                    for role in roles:
                        self.del_permission_role(role, perm_view)
                    self.del_permission_view_menu(perm_view.permission.name, view_menu)
                elif perm_view not in role_admin.permissions:
                    # Role Admin must have all permissions
                    self.add_permission_role(role_admin, perm_view)

    def add_permissions_menu(self, view_menu_name):
        """
            Adds menu_access to menu on permission_view_menu

            :param view_menu_name: The menu name
        """
        self.add_view_menu(view_menu_name)
        pv = self.find_permission_view_menu("menu_access", view_menu_name)
        if not pv:
            pv = self.add_permission_view_menu("menu_access", view_menu_name)
        role_admin = self.find_role(self.auth_role_admin)
        self.add_permission_role(role_admin, pv)

    def security_cleanup(self, baseviews, menus, sides):
        """
            Will cleanup all unused permissions from the database

            :param baseviews: A list of BaseViews class
            :param menus: Menu class
        """
        viewsmenus = self.get_all_view_menu()
        roles = self.get_all_roles()
        for viewmenu in viewsmenus:
            found = False
            for baseview in baseviews:
                if viewmenu.name == baseview.class_permission_name:
                    found = True
                    break
            if menus.find(viewmenu.name):
                found = True
            if sides.find(viewmenu.name):
                found = True
            if not found:
                permissions = self.find_permissions_view_menu(viewmenu)
                for permission in permissions:
                    for role in roles:
                        self.del_permission_role(role, permission)
                    self.del_permission_view_menu(
                        permission.permission.name, viewmenu.name
                    )
                self.del_view_menu(viewmenu.name)
        self.security_converge(baseviews)

    @staticmethod
    def _get_new_old_permissions(baseview) -> Dict:
        ret = dict()
        for method_name, permission_name in baseview.method_permission_name.items():
            old_permission_name = baseview.previous_method_permission_name.get(
                method_name
            )
            # Actions do not get prefix when normally defined
            if (hasattr(baseview, 'actions') and
                    baseview.actions.get(old_permission_name)):
                permission_prefix = ''
            else:
                permission_prefix = c.PERMISSION_PREFIX
            if old_permission_name:
                if c.PERMISSION_PREFIX + permission_name not in ret:
                    ret[
                        c.PERMISSION_PREFIX + permission_name
                        ] = {permission_prefix + old_permission_name, }
                else:
                    ret[
                        c.PERMISSION_PREFIX + permission_name
                        ].add(permission_prefix + old_permission_name)
        return ret

    @staticmethod
    def _add_state_transition(
            state_transition: Dict,
            old_view_name: str,
            old_perm_name: str,
            view_name: str,
            perm_name: str
    ) -> None:
        old_pvm = state_transition['add'].get((old_view_name, old_perm_name))
        if old_pvm:
            state_transition['add'][(old_view_name, old_perm_name)].add(
                (view_name, perm_name)
            )
        else:
            state_transition['add'][(old_view_name, old_perm_name)] = {
                (view_name, perm_name)
            }
        state_transition['del_role_pvm'].add((old_view_name, old_perm_name))
        state_transition['del_views'].add(old_view_name)
        state_transition['del_perms'].add(old_perm_name)

    @staticmethod
    def _update_del_transitions(state_transitions: Dict, baseviews: List) -> None:
        """
            Mutates state_transitions, loop baseviews and prunes all
            views and permissions that are not to delete because references
            exist.

        :param baseview:
        :param state_transitions:
        :return:
        """
        for baseview in baseviews:
            state_transitions['del_views'].discard(baseview.class_permission_name)
            for permission in baseview.base_permissions:
                state_transitions['del_role_pvm'].discard(
                    (
                        baseview.class_permission_name,
                        permission
                    )
                )
                state_transitions['del_perms'].discard(permission)

    def create_state_transitions(self, baseviews: List) -> Dict:
        """
            Creates a Dict with all the necessary vm/permission transitions

            Dict: {
                    "add": {(<VM>, <PERM>): ((<VM>, PERM), ... )}
                    "del_role_pvm": ((<VM>, <PERM>), ...)
                    "del_views": (<VM>, ... )
                    "del_perms": (<PERM>, ... )
                  }

        :param baseviews: List with all the registered BaseView, BaseApi
        :param menus: List with all the menu entries
        :return: Dict with state transitions
        """
        state_transitions = {
            'add': {},
            'del_role_pvm': set(),
            'del_views': set(),
            'del_perms': set()
        }
        for baseview in baseviews:
            add_all_flag = False
            new_view_name = baseview.class_permission_name
            permission_mapping = self._get_new_old_permissions(baseview)
            if baseview.previous_class_permission_name:
                old_view_name = baseview.previous_class_permission_name
                add_all_flag = True
            else:
                new_view_name = baseview.class_permission_name
                old_view_name = new_view_name
            for new_perm_name in baseview.base_permissions:
                if add_all_flag:
                    old_perm_names = permission_mapping.get(new_perm_name)
                    old_perm_names = old_perm_names or (new_perm_name,)
                    for old_perm_name in old_perm_names:
                        self._add_state_transition(
                            state_transitions,
                            old_view_name,
                            old_perm_name,
                            new_view_name,
                            new_perm_name
                        )
                else:
                    old_perm_names = permission_mapping.get(new_perm_name) or set()
                    for old_perm_name in old_perm_names:
                        self._add_state_transition(
                            state_transitions,
                            old_view_name,
                            old_perm_name,
                            new_view_name,
                            new_perm_name
                        )
        self._update_del_transitions(state_transitions, baseviews)
        return state_transitions

    def security_converge(self, baseviews: List, dry=False) -> Dict:
        """
            Converges overridden permissions on all registered views/api
            will compute all necessary operations from `class_permissions_name`,
            `previous_class_permission_name`, method_permission_name`,
            `previous_method_permission_name` class attributes.

        :param baseviews: List of registered views/apis
        :param menus: List of menu items
        :param dry: If True will not change DB
        :return: Dict with the necessary operations (state_transitions)
        """
        state_transitions = self.create_state_transitions(baseviews)
        if dry:
            return state_transitions
        if not state_transitions:
            log.info("No state transitions found")
            return dict()
        log.debug(f"State transitions: {state_transitions}")
        roles = self.get_all_roles()
        for role in roles:
            permissions = list(role.permissions)
            for pvm in permissions:
                new_pvm_states = state_transitions['add'].get(
                    (pvm.view_menu.name, pvm.permission.name)
                )
                if not new_pvm_states:
                    continue
                for new_pvm_state in new_pvm_states:
                    new_pvm = self.add_permission_view_menu(
                        new_pvm_state[1], new_pvm_state[0]
                    )
                    self.add_permission_role(role, new_pvm)
                if (pvm.view_menu.name, pvm.permission.name) in state_transitions[
                    'del_role_pvm'
                ]:
                    self.del_permission_role(role, pvm)
        for pvm in state_transitions['del_role_pvm']:
            self.del_permission_view_menu(pvm[1], pvm[0], cascade=False)
        for view_name in state_transitions['del_views']:
            self.del_view_menu(view_name)
        for permission_name in state_transitions['del_perms']:
            self.del_permission(permission_name)
        return state_transitions

    """
     ---------------------------
     INTERFACE ABSTRACT METHODS
     ---------------------------
    """

    """
    ----------------------
     PRIMITIVES FOR ROLES
    ----------------------
    """

    def find_role(self, name):
        raise NotImplementedError

    def find_role_by_id(self, pk):
        raise NotImplementedError

    def add_role(self, name):
        raise NotImplementedError

    def update_role(self, pk, name):
        raise NotImplementedError

    def get_all_roles(self):
        raise NotImplementedError

    def del_role(self, pk):
        raise NotImplementedError

    """
    ----------------------------
     PRIMITIVES FOR PERMISSIONS
    ----------------------------
    """

    def get_public_role(self):
        """
            returns all permissions from public role
        """
        raise NotImplementedError

    def get_public_permissions(self):
        """
            returns all permissions from public role
        """
        raise NotImplementedError

    def find_permission(self, name):
        """
            Finds and returns a Permission by name
        """
        raise NotImplementedError

    def find_roles_permission_view_menus(
            self,
            permission_name: str,
            role_ids: List[int],
    ):
        raise NotImplementedError

    def find_permission_view_by_roles(
            self,
            role_ids: List[int],
    ):
        raise NotImplementedError

    def exist_permission_on_roles(
            self,
            view_name: str,
            permission_name: str,
            role_ids: List[int],
    ) -> bool:
        """
            Finds and returns permission views for a group of roles
        """
        raise NotImplementedError

    def add_permission(self, name):
        """
            Adds a permission to the backend, models permission

            :param name:
                name of the permission: 'can_add','can_edit' etc...
        """
        raise NotImplementedError

    def del_permission(self, name):
        """
            Deletes a permission from the backend, models permission

            :param name:
                name of the permission: 'can_add','can_edit' etc...
        """
        raise NotImplementedError

    """
    ----------------------
     PRIMITIVES VIEW MENU
    ----------------------
    """

    def find_view_menu(self, name):
        """
            Finds and returns a ViewMenu by name
        """
        raise NotImplementedError

    def get_all_view_menu(self):
        raise NotImplementedError

    def add_view_menu(self, name):
        """
            Adds a views or menu to the backend, models view_menu
            param name:
                name of the views menu to add
        """
        raise NotImplementedError

    def del_view_menu(self, name):
        """
            Deletes a ViewMenu from the backend

            :param name:
                name of the ViewMenu
        """
        raise NotImplementedError

    """
    ----------------------
     PERMISSION VIEW MENU
    ----------------------
    """

    def find_permission_view_menu(self, permission_name, view_menu_name):
        """
            Finds and returns a PermissionView by names
        """
        raise NotImplementedError

    def find_permission_view_menu_by_id(self, pk):
        """
            Finds and returns a PermissionView by names
        """
        raise NotImplementedError

    def find_permissions_view_menu(self, view_menu):
        """
            Finds all permissions from ViewMenu, returns list of PermissionView

            :param view_menu: ViewMenu object
            :return: list of PermissionView objects
        """
        raise NotImplementedError

    def add_permission_view_menu(self, permission_name, view_menu_name):
        """
            Adds a permission on a views or menu to the backend

            :param permission_name:
                name of the permission to add: 'can_add','can_edit' etc...
            :param view_menu_name:
                name of the views menu to add
        """
        raise NotImplementedError

    def del_permission_view_menu(self, permission_name, view_menu_name, cascade=True):
        raise NotImplementedError

    def exist_permission_on_views(self, lst, item):
        raise NotImplementedError

    def exist_permission_on_view(self, lst, permission, view_menu):
        raise NotImplementedError

    def add_permission_role(self, role, perm_view):
        """
            Add permission-ViewMenu object to Role

            :param role:
                The role object
            :param perm_view:
                The PermissionViewMenu object
        """
        raise NotImplementedError

    def del_permission_role(self, role, perm_view):
        """
            Remove permission-ViewMenu object to Role

            :param role:
                The role object
            :param perm_view:
                The PermissionViewMenu object
        """
        raise NotImplementedError

    def update_permission_role(self, role, perm_views):
        """
            Remove permission-ViewMenu object to Role

            :param role:
                The role object
            :param perm_view:
                The PermissionViewMenu object
        """
        raise NotImplementedError
