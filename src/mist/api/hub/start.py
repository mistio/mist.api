if __name__ == "__main__":
    import gevent
    import gevent.socket
    import gevent.monkey
    gevent.monkey.patch_all()
    import mist.api.hub.main
    from mist.api.hub.shell import LoggingShellHubWorker
    mist.api.hub.main.main(workers={'shell': LoggingShellHubWorker})
