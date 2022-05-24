#!/usr/bin/env python3

from mist.api.config import TAGS_RESOURCE_TYPES
from mist.api.helpers import get_resource_model
from mist.api.tag.methods import get_tags_for_resource
from mist.api.models import Cloud  # noqa F401


def check_difference(owner, resource_object, override=False):

    canonical = get_tags_for_resource(owner, resource_object)
    tags_attribute = resource_object.tags_to_dict()

    if canonical != tags_attribute:

        print_diff(canonical, tags_attribute, resource_object)
        resource_object.tags = resource_object.tags_to_string(canonical)
        resource_object.save()
        check_difference(owner, resource_object, override=True)

    elif override:
        print(15 * '-', 'Fixing', 15 * '-')
        print_diff(canonical, tags_attribute, resource_object)


def print_diff(canonical, tags_attribute, resource_object):
    canon_minus_atrr = canonical.items() - tags_attribute.items()
    attr_minus_canon = tags_attribute.items() - canonical.items()
    print(f"{resource_object._meta['collection']} {resource_object.id}: \n\
            canonical: {canonical} \n \
            tags_attribute: {tags_attribute} \n \
            canonical - attribute = {canon_minus_atrr} \n \
            attribute - canonical =   {attr_minus_canon} \n \
            ")


def main():
    for resource_type in TAGS_RESOURCE_TYPES:
        try:
            resource_model = get_resource_model(resource_type.rstrip('s'))
        except KeyError:
            continue
        for resource_object in resource_model.objects():
            try:
                owner = resource_object.owner
            except AttributeError:
                owner = resource_object.cloud.owner

            check_difference(owner, resource_object)


if __name__ == "__main__":
    main()
