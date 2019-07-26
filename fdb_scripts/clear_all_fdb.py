import fdb
fdb.api_version(610)

import fdb.tuple


def init_db():
    db = fdb.open()
    return db


@fdb.transactional
def clear_db(tr):
    del tr[monitoring.range(())]  # clear the directory


if __name__ == '__main__':
    print('clearing fdb..')
    db = init_db()
    if fdb.directory.exists(db, 'monitoring'):
        monitoring = fdb.directory.open(db, ('monitoring',))
        clear_db(db)
        print('All clear.')
    else:
        print('The directory you are trying to clear does not exist.')
