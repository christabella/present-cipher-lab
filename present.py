#!/usr/bin/env python3

# Present skeleton file for 50.020 Security
# Oka, SUTD, 2014

#constants
fullround=32

#S-Box Layer
sbox=[0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2]

#PLayer
pmt=[0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,\
     4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,\
     8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,\
     12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63]

# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def genRoundKeys(key, rounds=32):
    roundkeys = []
    for i in range(1, rounds+1):
        '''
        At round i the 64-bit round key Ki = k63 k62 . . . k0 consists 
        of the 64 leftmost bits of the current contents of register K:
        K_i = k63 k62 ...k0 = k79 k78 ...k16      
        '''
        roundkeys.append(key >> 16)

        # After extracting Ki, the key register K = k79k78 . . . k0 is updated:

        # the key register is rotated by 61 bit positions to the left
        key = rol(key, 61, 80)

        # the left-most four bits are passed through the present S-box
        leftmost_four = key >> 76
        sboxed_leftmost_four = sbox[leftmost_four] << 76 
        rightmost_76 = (key & int('1' * 76, base=2))
        key = sboxed_leftmost_four + rightmost_76

        # the round_counter value i is exclusive-ored with bits k19 k18 k17 k16 k15 
        # of K with the least significant bit of round_counter on the right
        key ^= i << 15 
    return roundkeys

def addRoundKey(state,Ki):
    return state ^ Ki

############################ Encryption ############################

def sBoxLayer(state, inv=False):
    '''
    the current state b63 . . . b0 is considered as sixteen 4-bit words w15 ...w0 where 
    wi = b4_i+3||b4_i+2||b4_i+1||b4_i for 0 <= i <= 15 and the output nibble S[wi]
    provides the updated state values in the obvious way.
    '''
    new_state = 0

    for i in range(16):
        word = (state >> i*4) & 0b1111
        if inv:
            new_state += sbox.index(word) << i*4
        else:            
            new_state += sbox[word] << i*4

    return new_state

def pLayer(state, inv=False):
    '''
    Bit i of state is moved to bit position P(i).
    P9I0 is the table `pmt`
    '''
    new_state = 0

    for i in range(64):
        bit = (state >> i) & 0b1
        if inv:
            position = pmt.index(i)
        else:
            position = pmt[i]
        new_state += bit << position

    return new_state

def present_rounds(plain, key, rounds=32):
    '''
    As described in Fig. 1: "A top-level algorithmic description of present"
    at http://yannickseurin.free.fr/pubs/Bogdanov_et_al07_CHES.pdf
    '''
    state = plain
    roundkeys = genRoundKeys(key, rounds)

    for i in range(rounds-1):
        state = addRoundKey(state, roundkeys[i])
        state = sBoxLayer(state)
        state = pLayer(state)
    state = addRoundKey(state, roundkeys[rounds-1])

    return state

def present(plain, key):
    return present_rounds(plain, key, fullround)

############################ Decryption ############################

def present_rounds_inv(cipher, key, rounds=32):
    '''
    As described in Fig. 1: "A top-level algorithmic description of present"
    at http://yannickseurin.free.fr/pubs/Bogdanov_et_al07_CHES.pdf
    '''
    state = cipher
    roundkeys = genRoundKeys(key, rounds)

    for i in range(rounds-1, 0, -1):
        state = addRoundKey(state, roundkeys[i])
        state = pLayer(state, inv=True)
        state = sBoxLayer(state, inv=True)
    state = addRoundKey(state, roundkeys[0])

    return state

def present_inv(cipher, key):
    return present_rounds_inv(cipher, key, fullround)

################################# Main #################################

if __name__=="__main__":

    plain1 = 2319952166299770930
    key1 = 123456
    cipher1 = present(plain1,key1)
    plain11 = present_inv(0x8009755c6b9dd96,key1)
    print(format(cipher1,'x'))
    # print(format(plain1,'x'))
    print(plain1)
    print(cipher1)
    assert plain1 == plain11

    plain2 = 0x0000000000000000
    key2 = 0xFFFFFFFFFFFFFFFFFFFF
    cipher2 = present(plain2,key2)
    plain22 = present_inv(cipher2,key2)
    # print(format(cipher2,'x'))
    # print(format(plain22,'x'))
    assert plain2 == plain22

    plain3 = 0xFFFFFFFFFFFFFFFF
    key3 = 0x00000000000000000000
    cipher3 = present(plain3,key3)
    plain33 = present_inv(cipher3,key3)
    # print(format(cipher3,'x'))
    # print(format(plain33,'x'))
    assert plain3 == plain33

    plain4 = 0xFFFFFFFFFFFFFFFF
    key4 = 0xFFFFFFFFFFFFFFFFFFFF
    cipher4 = present(plain4,key4)
    plain44 = present_inv(cipher4,key4)
    # print(format(cipher4,'x'))
    # print(format(plain44,'x'))
    assert plain4 == plain44


