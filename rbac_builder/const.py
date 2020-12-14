LOGMSG_ERR_SEC_ACCESS_DENIED = "Access is Denied for: {0} on: {1}"
""" Access denied log message, format with user and views/resource """
LOGMSG_WAR_SEC_LOGIN_FAILED = "Login Failed for user: {0}"
LOGMSG_ERR_SEC_CREATE_DB = "DB Creation and initialization failed: {0}"
""" security models creation fails, format with error message """
LOGMSG_ERR_SEC_ADD_ROLE = "Add Role: {0}"
""" Error adding role, format with err message """
LOGMSG_ERR_SEC_ADD_PERMISSION = "Add Permission: {0}"
""" Error adding permission, format with err message """
LOGMSG_ERR_SEC_ADD_VIEWMENU = "Add View Menu Error: {0}"
""" Error adding views menu, format with err message """
LOGMSG_ERR_SEC_DEL_PERMISSION = "Del Permission Error: {0}"
""" Error deleting permission, format with err message """
LOGMSG_ERR_SEC_ADD_PERMVIEW = "Creation of Permission View Error: {0}"
""" Error adding permission views, format with err message """
LOGMSG_ERR_SEC_DEL_PERMVIEW = "Remove Permission from View Error: {0}"
""" Error deleting permission views, format with err message """
LOGMSG_WAR_SEC_DEL_PERMVIEW = (
    "Refused to delete permission views, assoc with role exists {}.{} {}"
)
LOGMSG_WAR_SEC_DEL_PERMISSION = (
    "Refused to delete, permission {} does not exist"
)
LOGMSG_WAR_SEC_DEL_VIEWMENU = (
    "Refused to delete, views menu {} does not exist"
)
LOGMSG_WAR_SEC_DEL_PERM_PVM = (
    "Refused to delete permission {}, PVM exists {}"
)
LOGMSG_WAR_SEC_DEL_VIEWMENU_PVM = (
    "Refused to delete views menu {}, PVM exists {}"
)
LOGMSG_ERR_SEC_ADD_PERMROLE = "Add Permission to Role Error: {0}"
""" Error adding permission to role, format with err message """
LOGMSG_ERR_SEC_DEL_PERMROLE = "Remove Permission to Role Error: {0}"
""" Error deleting permission to role, format with err message """
LOGMSG_ERR_SEC_ADD_REGISTER_USER = "Add Register User Error: {0}"
""" Error adding registered user, format with err message """
LOGMSG_ERR_SEC_DEL_REGISTER_USER = "Remove Register User Error: {0}"
""" Error deleting registered user, format with err message """
LOGMSG_ERR_SEC_NO_REGISTER_HASH = "Attempt to activate user with false hash: {0}"
""" Attempt to activate user with not registered hash, format with hash """
LOGMSG_ERR_SEC_AUTH_LDAP = "LDAP Error {0}"
""" Generic LDAP error, format with err message """
LOGMSG_ERR_SEC_AUTH_LDAP_TLS = (
    "LDAP Could not activate TLS on established connection with {0}"
)
""" LDAP Could not activate TLS on established connection with server """
LOGMSG_ERR_SEC_ADD_USER = "Error adding new user to database. {0}"
""" Error adding user, format with err message """
LOGMSG_ERR_SEC_UPD_USER = "Error updating user to database. {0} "
""" Error updating user, format with err message """
LOGMSG_WAR_SEC_NO_USER = "No user yet created, use flask fab command to do it."
""" Warning when app starts if no user exists on db """
LOGMSG_WAR_SEC_NOLDAP_OBJ = (
    "User self registration failed no LDAP object found for: {0}"
)

LOGMSG_INF_SEC_ADD_PERMVIEW = "Created Permission View: {0}"
""" Info when adding permission views, format with permission views class string """
LOGMSG_INF_SEC_DEL_PERMVIEW = "Removed Permission View: {0} on {1}"
""" Info when deleting permission views, format with permission name and views name """
LOGMSG_INF_SEC_ADD_PERMROLE = "Added Permission {0} to role {1}"
""" Info when adding permission to role,
format with permission views class string and role name """
LOGMSG_INF_SEC_DEL_PERMROLE = "Removed Permission {0} to role {1}"
""" Info when deleting permission to role,
format with permission views class string and role name """
LOGMSG_INF_SEC_ADD_ROLE = "Inserted Role: {0}"
""" Info when added role, format with role name """
LOGMSG_INF_SEC_NO_DB = "Security DB not found Creating all Models from Base"
LOGMSG_INF_SEC_ADD_DB = "Security DB Created"
LOGMSG_INF_SEC_ADD_USER = "Added user {0}"
""" User added, format with username """
LOGMSG_INF_SEC_UPD_USER = "Updated user {0}"
""" User updated, format with username """
LOGMSG_INF_SEC_UPD_ROLE = "Updated role {0}"
""" Role updated, format with role name """
LOGMSG_ERR_SEC_UPD_ROLE = "An error occurred updating role {0}"
""" Role updated Error, format with role name """

LOGMSG_INF_RBAC_ADDON_ADDED = "Registered AddOn: {0}"
""" Addon imported and registered """
LOGMSG_ERR_RBAC_ADDON_IMPORT = "An error occurred when importing declared addon {0}: {1}"
""" Error on addon import, format with addon class path and error message """
LOGMSG_ERR_RBAC_ADDON_PROCESS = (
    "An error occurred when processing declared addon {0}: {1}"
)
""" Error on addon processing (pre, register, post),
format with addon class path and error message """


LOGMSG_ERR_RBAC_ADD_PERMISSION_MENU = "Add Permission on Menu Error: {0}"
""" Error when adding a permission to a menu, format with err """
LOGMSG_ERR_RBAC_ADD_PERMISSION_VIEW = "Add Permission on View Error: {0}"
""" Error when adding a permission to a menu, format with err """

LOGMSG_ERR_DBI_ADD_GENERIC = "Add record error: {0}"
""" Database add generic error, format with err message """
LOGMSG_ERR_DBI_EDIT_GENERIC = "Edit record error: {0}"
""" Database edit generic error, format with err message """
LOGMSG_ERR_DBI_DEL_GENERIC = "Delete record error: {0}"
""" Database delete generic error, format with err message """
LOGMSG_WAR_DBI_AVG_ZERODIV = "Zero division on aggregate_avg"

LOGMSG_WAR_RBAC_VIEW_EXISTS = "View already exists {0} ignoring"
""" Attempt to add an already added views, format with views name """
LOGMSG_WAR_DBI_ADD_INTEGRITY = "Add record integrity error: {0}"
""" Dabase integrity error, format with err message """
LOGMSG_WAR_DBI_EDIT_INTEGRITY = "Edit record integrity error: {0}"
""" Dabase integrity error, format with err message """
LOGMSG_WAR_DBI_DEL_INTEGRITY = "Delete record integrity error: {0}"
""" Dabase integrity error, format with err message """

LOGMSG_INF_RBAC_ADD_VIEW = "Registering class {0} on menu {1}"
""" Inform that views class was added, format with class name, name"""

FLAMSG_ERR_SEC_ACCESS_DENIED = "Access is Denied"

PERMISSION_PREFIX = "can_"
