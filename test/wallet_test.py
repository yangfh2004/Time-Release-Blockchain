from wallet import send_transaction

if __name__ == '__main__':
    addr_from = "2NFbCmn8O7stZ8cJTo8rKXGCs8ZaIry1eBZk5XAzI6w0KorYSAQV1Hi20C8Sa6/3vfwY7gq4ZBdfHUWHfqZDcA=="
    addr_to = "2NFbCmn8O7stZ8cJTo8rKXGCs8ZaIry1eBZk5XAzI6w0KorYSAQV1Hi20C8Sa6/3vfwY7gq4ZBdfHUWHfqZDcA=="
    tx_private_key = "6ab791fa693fd54066f88de0e794fc660e7b243155b4bcbde5aaf16844941589"
    message = "I have a secret"
    lock_time = 120
    send_transaction(addr_from, tx_private_key, addr_to, 1, message, lock_time)
