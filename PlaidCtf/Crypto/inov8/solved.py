import z3
import struct
import sys


data = []
filename = "innov8_excav8.d35e5bf36e3e6438dd960aa7adeeb1dcbb25479bddd96509ba72968e1238b488/innov8_excav8/output.txt"
with open(filename, 'r') as f:
    for line in f:
        data.append(float(line))

def return_next_term(sequence):
    sequence = sequence[::-1]

    solver = z3.Solver()

    se_state0, se_state1 = z3.BitVecs("se_state0 se_state1", 64)

    for i in range(len(sequence)):
        se_s1 = se_state0
        se_s0 = se_state1
        se_state0 = se_s0
        se_s1 ^= se_s1 << 23
        se_s1 ^= z3.LShR(se_s1, 17)  # Logical shift instead of Arthmetric shift
        se_s1 ^= se_s0
        se_s1 ^= z3.LShR(se_s0, 26)
        se_state1 = se_s1

        float_64 = struct.pack("d", sequence[i] + 1)
        u_long_long_64 = struct.unpack("<Q", float_64)[0]

        mantissa = u_long_long_64 & ((1 << 52) - 1)

        solver.add(int(mantissa) == z3.LShR(se_state0, 12))


    if solver.check() == z3.sat:
        model = solver.model()
        states = {}
        for state in model.decls():
            states[state.__str__()] = model[state]

        #print(states)

        state0 = states["se_state0"].as_long()
        u_long_long_64 = (state0 >> 12) | 0x3FF0000000000000
        float_64 = struct.pack("<Q", u_long_long_64)
        next_sequence = struct.unpack("d", float_64)[0]
        next_sequence -= 1

        return next_sequence

secretbits = ""


for i in range(len(data)//24):
    print(i)
    block = data[24*i:24*(i+1)]
    if return_next_term(block[:23]) is not None:
        secretbits += "1"
    else:
        secretbits += "0"

print(secretbits)

n = [secretbits[i:i+8] for i in range(0, len(secretbits), 8)]

original_string = ''.join(chr(int(b, 2)) for b in n)

print(original_string)
