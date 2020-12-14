from typing import List

from flask import current_app


class MenuItem(object):
    def __init__(self, name, href="", icon="", label="", childs=None, baseview=None):
        self.name = name
        self.href = href
        self.icon = icon
        self.label = label
        self.childs = childs or []
        self.baseview = baseview

    def __repr__(self):
        return self.name

    def to_json(self):
        return {
            'name': self.name,
            'childs': self.childs
        }


class Menu(object):
    def __init__(self):
        self.menu = []
        self.group = None

    def get_list(self):
        return self.menu

    def get_flat_name_list(self, menu=None, result: List = None) -> List:
        menu = menu or self.menu
        result = result or []
        for item in menu:
            result.append(item.name)
            if item.childs:
                result.extend(self.get_flat_name_list(menu=item.childs))
        return result

    def get_data(self, menu=None):
        menu = menu or self.menu
        ret_list = []

        allowed_menus = current_app.rbac_builder.sm.get_user_menu_access(
            self.get_flat_name_list()
        )

        for i, item in enumerate(menu):
            if item and item.name == '-' and not i == len(menu) - 1:
                ret_list.append('-')
            elif item and item.name not in allowed_menus:
                continue
            elif item and item.childs:
                ret_list.append({
                    "name": item.name,
                    "icon": item.icon,
                    "label": str(item.label),
                    "childs": self.get_data(menu=item.childs)
                })
            else:
                if item:
                    ret_list.append({
                        "name": item.name,
                        "icon": item.icon,
                        "label": str(item.label),
                        "url": item.href
                    })
        return ret_list

    def find(self, name, menu=None):
        """
            Finds a menu item by name and returns it.

            :param name:
                The menu item name.
        """
        menu = menu or self.menu
        for i in menu:
            if i.name == name:
                return i
            else:
                if i.childs:
                    ret_item = self.find(name, menu=i.childs)
                    if ret_item:
                        return ret_item

    def add_category(self, category, icon="", label="", parent_category=""):
        label = label or category
        if parent_category == "":
            self.menu.append(MenuItem(name=category, icon=icon, label=label))
        else:
            self.find(parent_category).childs.append(
                MenuItem(name=category, icon=icon, label=label)
            )

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
        label = label or name
        category_label = category_label or category
        if category == "":
            self.menu.append(
                MenuItem(
                    name=name, href=href, icon=icon, label=label, baseview=baseview
                )
            )
        else:
            menu_item = self.find(category)
            if menu_item:
                new_menu_item = MenuItem(
                    name=name, href=href, icon=icon, label=label, baseview=baseview
                )
                menu_item.childs.append(new_menu_item)
            else:
                self.add_category(
                    category=category, icon=category_icon, label=category_label, parent_category=parent_category
                )
                new_menu_item = MenuItem(
                    name=name, href=href, icon=icon, label=label, baseview=baseview
                )
                self.find(category).childs.append(new_menu_item)

    def add_separator(self, category=""):
        menu_item = self.find(category)
        if menu_item:
            menu_item.childs.append(MenuItem("-"))
        else:
            raise Exception(
                "Menu separator does not have correct category {}".format(category))


class SideItem(object):
    def __init__(self, name, href="", label="", items=None):
        self.name = name
        self.href = href
        self.label = label
        self.items = items

    def __repr__(self):
        return self.name

    def to_json(self):
        return {
            'name': self.name,
            'href': self.href,
            'label': self.label,
            'items': self.items
        }


class Side(object):
    menu = None

    def __init__(self, menu):
        self.side = {}
        self.menu = menu

    @property
    def get_side(self):
        return self.side

    def get_flat_name_list(self) -> List:
        return list(self.side.keys())

    def find(self, name):
        """
            Finds a menu item by name and returns it.

            :param name:
                The menu item name.
        """
        return self.side[name] if name in self.side else None

    def add_side(
            self,
            name,
            href="",
            label=""
    ):
        if name not in self.side:
            self.side[name] = SideItem(name, href, label, [])

    def add_menu_to_side(
            self,
            name,
            menu
    ):
        if name in self.side:
            self.side[name].items.append(menu)

    def get_data(self):
        ret_object = {}

        allowed_sides = current_app.rbac_builder.sm.get_user_menu_access(
            self.get_flat_name_list()
        )

        for side in allowed_sides:
            if side in self.side:
                ret_object[side] = {
                    'name': self.side[side].name,
                    'href': self.side[side].href,
                    'label': self.side[side].label,
                    'items': self.menu.get_data(self.side[side].items)
                }
        return ret_object
