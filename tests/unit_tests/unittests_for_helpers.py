""" Unittests for mist.api.helpers functions """


def test_convert_to_datetime():
    from datetime import datetime
    from mist.api.helpers import convert_to_datetime
    valid_inputs = ['300s', '10m', '2h', '5d', '3w', '10mo']
    outputs = []
    for inp in valid_inputs:
        outputs.append(convert_to_datetime(inp))
    for output in outputs:
        assert type(output) == datetime, ('Expected datetime type of output '
                                          'but got something else!')
    hours = outputs[2] - datetime.now()
    assert hours.seconds / 3600 < 2, ("2h input resulted in greater than 2 "
                                      "hours timedelta!")
    days = outputs[3] - datetime.now()
    assert days.days == 4, ('5d input did not result in a 5 day timedelta!')
    weeks = outputs[4] - datetime.now()
    assert weeks.days == 20, ('3w input did not result in a 21 days time diff')
    invalid_input = '50hours'
    try:
        convert_to_datetime(invalid_input)
    except ValueError:
        print("Got correct error!")
    except Exception as exc:
        raise ValueError(f"Got incorrect error: {exc}")
