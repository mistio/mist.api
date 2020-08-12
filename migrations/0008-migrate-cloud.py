#!/usr/bin/env python

import sys

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.networks.models import Network


def get_resource_by_id(cloud, resource, resource_type):
# for machines, we store 'machine_id' instead of 'external_id'
    if resource_type.__name__ == 'Machine':
        new_resource = Machine.objects.get(cloud=cloud,
                                            machine_id=resource.machine_id,
                                            missing_since=None)

    elif resource_type.__name__ == 'Network':
        new_resource = Network.objects.get(cloud=cloud,
                                            network_id=resource.network_id,
                                            missing_since=None)
    return new_resource


def migrate_ownership(old_cloud, new_cloud):
    for resource_type in (Machine, Network):
        failed = migrated = 0
        old_resources = resource_type.objects.filter(cloud=old_cloud,
                                                     missing_since=None)
        print("*** Starting migrating {} {}s***".format(old_resources.count(),
                                                        resource_type.__name__))
        new_resources = resource_type.objects.filter(cloud=new_cloud,
                                                     missing_since=None)
        for resource in old_resources:
            try:
                new_resource = get_resource_by_id(new_cloud , resource, resource_type)
                new_resource.owned_by = resource.owned_by
                # also migrate `created_by` field
                new_resource.created_by = resource.created_by
                try:
                    new_resource.save()
                    print("Successfully migrated ownership of {} {}".format(resource_type.__name__,
                                                                            resource.name))
                    migrated += 1
                except Exception:
                    print("*** Could not migrate ownership of {} {} with mist id {} ***".format(resource_type.__name__,
                                                                                                resource.name,
                                                                                                resource.id))
            except resource_type.DoesNotExist:
                print("*** WARNING: {} {} with mist id {} was not found on new cloud. Could not migrate ownership ***".format(resource_type.__name__,
                                                                                                                              resource.name,
                                                                                                                              resource.id))
                failed += 1

        print("Successfully migrated {} {}s".format(migrated, resource_type.__name__))
        
        if failed:
            print("Failed to migrate {} {}s".format(migrated, resource_type.__name__))

def migrate_cloud(old_cloud_id, new_cloud_id):
    try:
        old_cloud = Cloud.objects.get(id=old_cloud_id)
    except Cloud.DoesNotExist:
        print("Cloud with id {} not found. Exiting...".format(old_cloud_id))
        sys.exit(1)
    try:
        new_cloud = Cloud.objects.get(id=new_cloud_id)
    except Cloud.DoesNotExist:
        print("Cloud with id {} not found. Exiting...".format(new_cloud_id))
    
    print("=====================================================================")
    print("=== Will migrate {} cloud to {} cloud ===".format(old_cloud.title, new_cloud.title))
    print("=====================================================================")
    migrate_ownership(old_cloud, new_cloud)
    return


if __name__ == '__main__':
    try:
        old_cloud_id = sys.argv[1]
        new_cloud_id = sys.argv[2]
    except IndexError:
        print("Old cloud id and new cloud id are required. Exiting...")
        sys.exit(1)

    migrate_cloud(old_cloud_id,new_cloud_id)


# ownership (machines, networks)

# tags
# key associations
# images