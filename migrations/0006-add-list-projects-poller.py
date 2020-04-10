def add_list_projects_polling_schedules():
    failed = 0
    clouds = Cloud.objects(deleted=None)

    for cloud in clouds:
        try:
            # TODO: verify that this triggers list_images()
            schedule = ListImagesPollingSchedule.add(cloud)
            schedule.set_default_interval(60 * 60 * 24)
            schedule.save()

        except Exception as exc:
            print('Error: %s') % exc
            traceback.print_exc()
            failed += 1
            continue

    print(' ****** Failures: ' + str(failed))

if __name__ == '__main__':
    add_list_projects_polling_schedules()
