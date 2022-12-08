from pymongo import MongoClient
from mist.api.config import MONGO_URI


def remove_control_plane_costs():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_machines = db['machines']
    db_clusters = db['clusters']

    print('Removing control_plane_hourly from machines ...')
    res = db_machines.update_many({}, {
        '$unset': {"cost.control_plane_hourly": 1}
    })
    print(f'{res.modified_count} machines were modified.')
    print('Removing control_plane_hourly from clusters ...')
    res = db_clusters.update_many({}, {
        '$unset': {"cost.control_plane_hourly": 1}
    })
    print(f'{res.modified_count} clusters were modified.')
    print('Removing control_plane_monthly from machines ...')
    res = db_machines.update_many({}, {
        '$unset': {"cost.control_plane_monthly": 1}
    })
    print(f'{res.modified_count} machines were modified.')
    print('Removing control_plane_monthly from clusters ...')
    res = db_clusters.update_many({}, {
        '$unset': {"cost.control_plane_monthly": 1}
    })
    print(f'{res.modified_count} clusters were modified.')


if __name__ == "__main__":
    remove_control_plane_costs()
