class StorageController(object):

    def __init__(self, volume):
        """Initialize the `StorageController` given a volume"""
        self.volume = volume
        self.cloud = volume.cloud

    def delete(self):
        """Delete `self.volume`"""
        return self.cloud.ctl.storage.delete_volume(self.volume)

    def rename(self, name):
        """Rename `self.volume`."""
        return self.cloud.ctl.storage.rename_volume(self.volume, name)

    def attach(self, node, **kwargs):
        """Attach `self.volume` to a node"""
        return self.cloud.ctl.storage.attach_volume(self.volume, node,
                                                    **kwargs)

    def detach(self, node):
        """Detach `self.volume` from a node"""
        return self.cloud.ctl.storage.detach_volume(self.volume, node)
