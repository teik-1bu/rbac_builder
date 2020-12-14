class BaseManager(object):
    """
        The parent class for all Managers
    """

    def __init__(self, rbac_builder):
        self.rbac_builder = rbac_builder

    def register_views(self):
        pass  # pragma: no cover

    def pre_process(self):
        pass  # pragma: no cover

    def post_process(self):
        pass  # pragma: no cover
