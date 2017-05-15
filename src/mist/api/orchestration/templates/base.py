import datetime


class BaseTemplateController(object):
    """The base Template Controller for all Template types.

    The `BaseTemplateController` defines common operations for all potential
    Template types, such as add, update, and delete.

    All Template subclasses should define their own `BaseTemplateController`
    subclass in order to account for Template-specific parsing and handling
    needs.

    All subclasses of the `BaseTemplateController` are located in
    `mist.api.orchestration.templates.controllers`.

    """

    def __init__(self, template):
        """Initialize a Template's controller given a `Template` instance."""
        self.template = template

    # TODO
    # def add(self, **kwargs):
    #     """"""

    def _add__parse_template(self):
        """Parse a Template.

        Each Template-specific controller should define its own method for
        parsing Templates in order to account for special handling/parsing
        of Template types.

        Subclasses of the `BaseTemplateController` MUST override this method.

        """
        raise NotImplementedError()

    # TODO
    # def update(self, **kwargs):
    #     """"""

    def delete(self, expire=False):
        """Delete a Template.

        By default the corresponding mongodb document is not actually deleted,
        but rather marked as deleted.

        If `expire` equals True, the document is expired from its collection.

        """
        self.template.update(set__deleted=datetime.datetime.utcnow())
        if expire is True:
            self.template.delete()
        # TODO: What if Stacks exist?

