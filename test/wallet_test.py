from wallet import send_transaction

if __name__ == '__main__':
    addr_from = "uWiVRoaGGKjH/WUcDyumsv05g0Y/o2qa1so9vcBMhm1cKwVJlefQ5O45SBEjykJSjwv1NV/qB6I0dnHR+ciF2Q=="
    addr_to = "uWiVRoaGGKjH/WUcDyumsv05g0Y/o2qa1so9vcBMhm1cKwVJlefQ5O45SBEjykJSjwv1NV/qB6I0dnHR+ciF2Q=="
    tx_private_key = "54aa2dbfed1ccf4d8377501a0b26e23b703300397a3f13f4895fc08311fefc73"
    message = "I have a secret"
    lock_time = 120
    send_transaction(addr_from, tx_private_key, addr_to, 1, message, lock_time)
