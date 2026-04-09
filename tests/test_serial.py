from micropki.serial import generate_unique_serial_int, serial_int_to_hex


def test_generate_unique_serial_is_positive():
    serial = generate_unique_serial_int()
    assert serial > 0


def test_generate_unique_serials_are_different():
    a = generate_unique_serial_int()
    b = generate_unique_serial_int()
    assert a != b


def test_serial_hex_conversion():
    serial = 123456789
    assert serial_int_to_hex(serial) == format(serial, "X")