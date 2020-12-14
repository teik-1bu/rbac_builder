import logging
from functools import reduce
from typing import Dict

from flask import current_app

from .const import (
    LOGMSG_ERR_RBAC_ADDON_IMPORT,
    LOGMSG_INF_RBAC_ADD_VIEW,
    LOGMSG_WAR_RBAC_VIEW_EXISTS,
    LOGMSG_ERR_RBAC_ADD_PERMISSION_VIEW,
    LOGMSG_ERR_RBAC_ADD_PERMISSION_MENU
)
from .menu import Menu, Side

log = logging.getLogger(__name__)


def dynamic_class_import(class_path):
    """
        Will dynamically import a class from a string path
        :param class_path: string with class path
        :return: class
    """
    # Split first occurrence of path
    try:
        tmp = class_path.split(".")
        module_path = ".".join(tmp[0:-1])
        package = __import__(module_path)
        return reduce(getattr, tmp[1:], package)
    except Exception as e:
        log.error(LOGMSG_ERR_RBAC_ADDON_IMPORT.format(class_path, e))


class RBACBuilder(object):
    baseviews = {}
    security_manager_class = None
    menu = None
    side = None

    # Flask app
    app = None
    # Database Session
    session = None
    # Security Manager Class
    sm = None
    # JWT
    jwt_manager = None

    def __init__(self, app=None, session=None, update_perms=True, security_manager_class=None, ):
        """
            Builder constructor
            :param app:
                The flask app object
            :param session:
                The SQLAlchemy session object
            :param update_perms:
            optional, update permissions flag (Boolean)
        """
        self.baseviews = {}

        self.menu = Menu()

        self.security_manager_class = security_manager_class

        self.side = Side(self.menu)

        self.app = app

        self.update_perms = update_perms

        if app is not None:
            self.init_app(app, session)

    def init_app(self, app, session, jwt_manager):
        """
            Will initialize the Flask app, supporting the app factory pattern.

            :param app:
            :param session: The SQLAlchemy session
            :param jwt_manager: JWT
        """
        self.app = app
        self.session = session
        self.jwt_manager = jwt_manager

        if self.security_manager_class is None:
            from rbac_builder.security.sqla.manager import SecurityManager
            self.security_manager_class = SecurityManager

        self.sm = self.security_manager_class(self)

    @property
    def get_app(self):
        """
            Get current or configured flask app

            :return: Flask App
        """
        if self.app:
            return self.app
        else:
            return current_app

    @property
    def get_session(self):
        """
            Get the current sqlalchemy session.

            :return: SQLAlchemy Session
        """
        return self.session

    @property
    def get_jwt_manager(self):
        """
            Get the current sqlalchemy session.

            :return: SQLAlchemy Session
        """
        return self.jwt_manager

    def get_view(self, name):
        """
            Get views by name

            :return: BaseView
        """
        return self.baseviews[name]

    def add_view(
            self,
            baseview,
            name,
            href="",
            icon="",
            label="",
            category="",
            category_icon="",
            category_label="",
            parent_category="", ):
        """
            Add your views associated with menus using this method.
        :param baseview:
            A BaseView type class instantiated or not.
            This method will instantiate the class for you if needed.
        :param name:
            The string name that identifies the menu.
        :param href:
            Override the generated href for the menu.
            You can use an url string or an endpoint name
            if non provided default_view from views will be set as href.
        :param icon:
            Font-Awesome icon name, optional.
        :param label:
            The label that will be displayed on the menu,
            if absent param name will be used
        :param category:
            The menu category where the menu will be included,
            if non provided the views will be acessible as a top menu.
        :param category_icon:
            Font-Awesome icon name for the category, optional.
        :param category_label:
            The label that will be displayed on the menu,
            if absent param name will be used
        """
        baseview = self._check_and_init(baseview)
        log.info(LOGMSG_INF_RBAC_ADD_VIEW.format(baseview.__class__.__name__, name))

        if not self._view_exists(baseview):
            baseview.rbac_builder = self
            self.baseviews[baseview.class_permission_name] = baseview
            if self.app:
                self._add_permission(baseview)
        else:
            log.warning(LOGMSG_WAR_RBAC_VIEW_EXISTS.format(baseview.__class__.__name__))

        self.add_menu(
            name=name,
            href=href,
            icon=icon,
            label=label,
            category=category,
            category_icon=category_icon,
            category_label=category_label,
            baseview=baseview,
            parent_category=parent_category,
        )
        return baseview

    def add_side(self, name, href="", label="", items=None):
        self.side.add_side(name, href, label)

        for i in items:
            menu = self.menu.find(i)
            self.side.add_menu_to_side(name, menu)

        if self.app:
            self._add_permissions_menu(name)

    def add_menu(
            self,
            name,
            href="",
            icon="",
            label="",
            category="",
            category_icon="",
            category_label="",
            parent_category="",
            baseview=None,
    ):
        """
            Add your own links to menu using this method

            :param name:
                The string name that identifies the menu.
            :param href:
                Override the generated href for the menu.
                You can use an url string or an endpoint name
            :param icon:
                Font-Awesome icon name, optional.
            :param label:
                The label that will be displayed on the menu,
                if absent param name will be used
            :param category:
                The menu category where the menu will be included,
                if non provided the views will be accessible as a top menu.
            :param category_icon:
                Font-Awesome icon name for the category, optional.
            :param category_label:
                The label that will be displayed on the menu,
                if absent param name will be used
            :param parent_category: parent category

        """
        self.menu.add_menu(
            name=name,
            href=href,
            icon=icon,
            label=label,
            category=category,
            category_icon=category_icon,
            category_label=category_label,
            parent_category=parent_category,
            baseview=baseview,
        )
        if self.app:
            self._add_permissions_menu(name)
            if category:
                self._add_permissions_menu(category)

    def add_view_no_menu(self, baseview):
        """
            Add your views without menu
        :param baseview:
        :return:
        """
        baseview = self._check_and_init(baseview)
        log.info(LOGMSG_INF_RBAC_ADD_VIEW.format(baseview.__class__.__name__, ""))

        if not self._view_exists(baseview):
            baseview.rbac_builder = self
            self.baseviews[baseview.class_permission_name] = baseview
            if self.app:
                self._add_permission(baseview)
        else:
            log.warning(LOGMSG_WAR_RBAC_VIEW_EXISTS.format(baseview.__class__.__name__))
        return baseview

    def _add_permission(self, baseview, update_perms=False):
        if self.update_perms or update_perms:
            try:
                self.sm.add_permissions_view(
                    baseview.base_permissions, baseview.class_permission_name
                )
            except Exception as e:
                log.error(LOGMSG_ERR_RBAC_ADD_PERMISSION_VIEW.format(str(e)))

    def _add_permissions_menu(self, name, update_perms=False):
        if self.update_perms or update_perms:
            try:
                self.sm.add_permissions_menu(name)
            except Exception as e:
                log.error(LOGMSG_ERR_RBAC_ADD_PERMISSION_MENU.format(str(e)))

    def _check_and_init(self, baseview):
        # If class if not instantiated, instantiate it
        if hasattr(baseview, "__call__"):
            baseview = baseview()
        return baseview

    def _view_exists(self, view):
        for key, baseview in self.baseviews.items():
            if baseview.__class__ == view.__class__:
                return True
        return False

    def security_cleanup(self):
        """
            This method is useful if you have changed
            the name of your menus or classes,
            changing them will leave behind permissions
            that are not associated with anything.

            You can use it always or just sometimes to
            perform a security cleanup. Warning this will delete any permission
            that is no longer part of any registered views or menu.

            Remember invoke ONLY AFTER YOU HAVE REGISTERED ALL VIEWS
        """
        self.sm.security_cleanup(list(self.baseviews.values()), self.menu, self.side)

    def security_converge(self, dry=False) -> Dict:
        """
            This method is useful when you use:

            - `class_permission_name`
            - `previous_class_permission_name`
            - `method_permission_name`
            - `previous_method_permission_name`

            migrates all permissions to the new names on all the Roles

        :param dry: If True will not change DB
        :return: Dict with all computed necessary operations
        """
        return self.sm.security_converge(list(self.baseviews.values()), dry)

    def get_all_permission(self):
        """
            This method is useful when you use:

            - `class_permission_name`
            - `previous_class_permission_name`
            - `method_permission_name`
            - `previous_method_permission_name`

            migrates all permissions to the new names on all the Roles

        :param dry: If True will not change DB
        :return: Dict with all computed necessary operations
        """
        return self.sm.security_converge(list(self.baseviews.values()), dry)
