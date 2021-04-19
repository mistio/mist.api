import unittest

from mist.api.helpers import search_parser


class TestSearchParser(unittest.TestCase):
    def test_empty_string(self):
        search = ''
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, [])

    def test_only_implicit_id_or_name(self):
        search = 'idorname'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['idorname'])

        search = 'id or name'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['id or name'])

        search = 'Id_o-r Name*'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['Id_o-r Name*'])

    def test_only_quoted_implicit_id_or_name(self):
        search = '"idorname"'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['"idorname"'])

        search = '"id or name"'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['"id or name"'])

        search = '"Id_o-r Name*"'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['"Id_o-r Name*"'])

    def test_implicit_id_or_name_with_other_key_value_pairs(self):
        search = 'id or name attr_1:value'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['id or name',
                                           'attr_1:value'])

        search = 'attr_1:value id or name attr_2=value'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value',
                                           'id or name',
                                           'attr_2=value'])

        search = 'attr_1=value id_or-name attr_2:value'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1=value',
                                           'id_or-name',
                                           'attr_2:value'])

    def test_quoted_implicit_id_or_name_with_other_key_value_pairs(self):
        search = '"id or name" attr_1:value'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['"id or name"',
                                           'attr_1:value'])

        search = 'attr_1:value "id or name" attr_2=value'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value',
                                           '"id or name"',
                                           'attr_2=value'])

        search = 'attr_1=value "id_or-name" attr_2:value'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1=value',
                                           '"id_or-name"',
                                           'attr_2:value'])

    def test_key_value_pairs_with_parentheses(self):
        search = ('attr_1:(value 1) attr_2=(value:2) attr_3:val3 '
                  'attr4:(value 4) attr5=(value 5) attr6:(value -6) '
                  'attr7=(value 7)')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'attr_2=value:2',
                                           'attr_3:val3',
                                           'attr4:value 4',
                                           'attr5=value 5',
                                           'attr6:value -6',
                                           'attr7=value 7',
                                           ])

    def test_key_value_pairs_with_parentheses_and_quotes(self):
        search = ('attr_1:(value 1) attr_2="value_2" attr_3:val-3 '
                  'attr4:(value4) attr5=(value 5) attr6:"value 6" '
                  'attr7="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'attr_2="value_2"',
                                           'attr_3:val-3',
                                           'attr4:value4',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'attr7="value 7"',
                                           ])

    def test_implicit_id_or_name_with_key_value_pairs_with_parentheses_and_quotes(self):  # noqa
        search = ('attr_1:(value 1) attr_2="value_2" id or name attr_3:val-3 '
                  'attr4:(value4) attr5=(value 5) '
                  'attr6:"value 6" attr7="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'attr_2="value_2"',
                                           'id or name',
                                           'attr_3:val-3',
                                           'attr4:value4',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'attr7="value 7"',
                                           ])

        search = ('id_or_name attr_1:(value 1) attr_2="value_2" '
                  'attr_3:val-3 attr4:(value4) '
                  'attr5=(value 5) attr6:"value 6" attr7="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['id_or_name',
                                           'attr_1:value 1',
                                           'attr_2="value_2"',
                                           'attr_3:val-3',
                                           'attr4:value4',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'attr7="value 7"',
                                           ])

    def test_mathematical_operators(self):
        search = 'attr_1<=val1 attr_2<=val2 attr_3>val3 attr_4!=(val 4)'
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1<=val1',
                                           'attr_2<=val2',
                                           'attr_3>val3',
                                           'attr_4!=val 4',
                                           ])

        search = ('attr_1:(value 1) attr_2>"value_2" id or name attr_3<val-3 '
                  'attr4<=(value4) attr5!=(value 5) '
                  'attr6!="value 6" attr7>="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'attr_2>"value_2"',
                                           'id or name',
                                           'attr_3<val-3',
                                           'attr4<=value4',
                                           'attr5!=value 5',
                                           'attr6!="value 6"',
                                           'attr7>="value 7"',
                                           ])

    def test_full(self):
        search = ('attr_1:(value 1) AND attr_2>"value 2" '
                  'OR attr_3:val-3 attr4:value4 '
                  'AND attr5=(value 5) attr6:"value 6" OR attr7!="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'AND',
                                           'attr_2>"value 2"',
                                           'OR',
                                           'attr_3:val-3',
                                           'attr4:value4',
                                           'AND',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'OR',
                                           'attr7!="value 7"',
                                           ])

    def test_full_implicit_id(self):
        search = ('attr_1!=(value 1) id or name AND attr_2="value 2" OR '
                  'attr_3:val-3 attr4:value4 '
                  'AND attr5=(value 5) attr6>="value 6" OR attr7="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1!=value 1',
                                           'id or name',
                                           'AND',
                                           'attr_2="value 2"',
                                           'OR',
                                           'attr_3:val-3',
                                           'attr4:value4',
                                           'AND',
                                           'attr5=value 5',
                                           'attr6>="value 6"',
                                           'OR',
                                           'attr7="value 7"',
                                           ])

        search = ('attr_1:(value 1) AND attr_2="value 2" OR attr_3:val-3 '
                  'id or name attr4:value4 '
                  'AND attr5=(value 5) attr6:"value 6" OR attr7="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'AND',
                                           'attr_2="value 2"',
                                           'OR',
                                           'attr_3:val-3',
                                           'id or name',
                                           'attr4:value4',
                                           'AND',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'OR',
                                           'attr7="value 7"',
                                           ])

        search = ('id_or_name attr_1:(value 1) AND attr_2="value 2" '
                  'OR attr_3:val-3 attr4:value4 '
                  'AND attr5=(value 5) attr6:"value 6" OR attr7="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['id_or_name',
                                           'attr_1:value 1',
                                           'AND',
                                           'attr_2="value 2"',
                                           'OR',
                                           'attr_3:val-3',
                                           'attr4:value4',
                                           'AND',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'OR',
                                           'attr7="value 7"',
                                           ])

        search = ('attr_1:(value 1) AND attr_2<="value 2" OR attr_3:val-3 '
                  '"id or name" attr4>value4 '
                  'AND attr5=(value 5) attr6:"value 6" OR attr7="value 7"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'AND',
                                           'attr_2<="value 2"',
                                           'OR',
                                           'attr_3:val-3',
                                           '"id or name"',
                                           'attr4>value4',
                                           'AND',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'OR',
                                           'attr7="value 7"',
                                           ])

        search = ('attr_1:(value 1) AND attr_2<="value 2" OR attr_3:val-3 '
                  'attr4>value4 AND attr5=(value 5) '
                  'attr6:"value 6" OR attr7="value 7" "id or name"')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'AND',
                                           'attr_2<="value 2"',
                                           'OR',
                                           'attr_3:val-3',
                                           'attr4>value4',
                                           'AND',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'OR',
                                           'attr7="value 7"',
                                           '"id or name"',
                                           ])

        search = ('attr_1:(value 1) AND attr_2<="value 2" OR attr_3:val-3 '
                  'attr4>value4 AND attr5=(value 5) '
                  'attr6:"value 6" OR attr7="value 7" id or name')
        parsed_list = search_parser(search)
        self.assertListEqual(parsed_list, ['attr_1:value 1',
                                           'AND',
                                           'attr_2<="value 2"',
                                           'OR',
                                           'attr_3:val-3',
                                           'attr4>value4',
                                           'AND',
                                           'attr5=value 5',
                                           'attr6:"value 6"',
                                           'OR',
                                           'attr7="value 7"',
                                           'id or name',
                                           ])


if __name__ == '__main__':
    unittest.main()
