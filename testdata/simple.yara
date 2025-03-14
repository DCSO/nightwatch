rule TestRule1
{
    strings:
        $test_string = "foo bar2"

    condition:
        $test_string
}
