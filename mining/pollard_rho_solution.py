from crypto.elgamal import PublicKey, PrivateKey, mod_exp
from crypto.pollard_rho import pollard_eqs_solver


class PRSolution:
    """Solution from pollard rho method."""
    def __init__(self, a1, a2, b1, b2, n, pubkey: PublicKey = None):
        self.a1 = a1
        self.a2 = a2
        self.b1 = b1
        self.b2 = b2
        self.n = n
        self.pubkey = pubkey

    @classmethod
    def from_str(cls, solution_str: str):
        """Generate a solution from a string."""
        nums = solution_str.split(',')
        if len(nums) < 5:
            raise ValueError("The input string is not valid")
        a1 = int(nums[0])
        a2 = int(nums[1])
        b1 = int(nums[2])
        b2 = int(nums[3])
        n = int(nums[4])
        return PRSolution(a1, a2, b1, b2, n)

    def _key_validate(self, x):
        prime = self.pubkey.p
        expected = self.pubkey.h
        actual = mod_exp(self.pubkey.g, x, prime)
        # test if the private key match the public key
        return expected == actual or prime == expected + actual

    def get_dict(self):
        return {"a1": self.a1, "a2": self.a2, "b1": self.b1, "b2": self.b2, "n": self.n}

    def generate_private_key(self):
        x = pollard_eqs_solver(self.a1, self.b1, self.a2, self.b2, self.n)
        if self.pubkey and self._key_validate(x):
            return PrivateKey(self.pubkey.p, self.pubkey.g, x, self.pubkey.bit_length)
        else:
            if self.pubkey is None:
                raise ValueError("Paired public key is missing!")
            else:
                raise ValueError("Solution is not valid!")

    def __repr__(self):
        return str(self.a1) + ", " + str(self.a2) + ", " + str(self.b1) + ", " + str(self.b2) + ", " + str(self.n)
