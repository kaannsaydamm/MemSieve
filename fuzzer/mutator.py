import random

from fuzzer.utils import cyclic_pattern

class Mutator:
    def __init__(self, initial_input: bytes):
        self.initial_input = initial_input

    def mutate(self) -> bytes:
        mutation_type = random.choice(['bit_flip', 'byte_inc', 'byte_dec', 'magic_byte', 'cyclic'])

        # If cyclic, disregard initial input and send pattern
        if mutation_type == 'cyclic':
            # Create a pattern slightly larger than initial input to provoke overflow
            size = max(len(self.initial_input) * 2, 4096)
            return cyclic_pattern(size).encode()

        data = bytearray(self.initial_input)
        
        if not data:
            return b'A' * 100 # Default if empty

        idx = random.randint(0, len(data) - 1)

        if mutation_type == 'bit_flip':
            bit = random.randint(0, 7)
            data[idx] ^= (1 << bit)
        elif mutation_type == 'byte_inc':
            data[idx] = (data[idx] + 1) % 256
        elif mutation_type == 'byte_dec':
            data[idx] = (data[idx] - 1) % 256
        elif mutation_type == 'magic_byte':
            # Insert potentially dangerous bytes
            magic = random.choice([0x00, 0xFF, 0x7F, 0x80, 0x0A, 0x0D])
            if random.choice([True, False]):
                data.insert(idx, magic) # Injection
            else:
                data[idx] = magic # Replacement

        return bytes(data)
