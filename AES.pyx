from libc.stdlib cimport malloc
from libc.stdio cimport fopen, fclose, FILE, fread, fwrite

cdef class AES:

    cdef readonly char[256] s_box
    cdef readonly char[256] inv_s_box
    cdef readonly char[24] rcon
    cdef unsigned char *key_shedule
    cdef int nk, nr

    def __init__(self, t, key_):
        cdef int i
        cdef unsigned char *key

        self.s_box = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

        self.inv_s_box = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                          0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                          0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                          0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                          0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                          0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                          0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                          0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                          0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                          0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                          0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                          0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                          0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                          0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                          0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                          0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]


        self.rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
                           0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a]

        self.nr = {128:10, 192:12, 256:14}[t]
        self.nk = {128:4, 192:6, 256:8}[t]

        key = <unsigned char *> malloc(len(key_) + 1)

        for i in range(len(key_)):
            key[i] = key_[i]
        self.key_shedule = <unsigned char *> malloc((self.nr + 1)*16 + 1)
        self.key_expansion(key)

    def __repr__(self):
        return str([self.key_shedule[i] for i in range(100)])

    cdef void key_expansion(self, unsigned char *key):

        cdef int i, j
        cdef unsigned char temp[4]

        for i in range(4 * self.nk):
            self.key_shedule[i] = key[i]
        for j in range(4):
            temp[j] =  key[4*self.nk - 4 + j]

        for i in range(self.nk, 4 * (self.nr + 1)):
            if not i % self.nk:
                temp[0], temp[1], temp[2], temp[3] = temp[1], temp[2], temp[3], temp[0]
                self.sub_bytes(4, temp)
                temp[0] ^= self.rcon[i // self.nk]
            elif self.nk > 6 and i % self.nk == 4:
                self.sub_bytes(4, temp)

            for j in range(4):
                self.key_shedule[4*i + j] = self.key_shedule[4*(i-self.nk) + j] ^ temp[j]
                temp[j] = self.key_shedule[4*i + j]

    cdef void add_round_key(self, unsigned char *state, int round_):
        """
        A round_ key is added to a given state
        Args:
            state: 
            round_:  
        """
        cdef int i
        for i in range(16):
            state[i] ^= self.key_shedule[round_*16 + i]



    cdef void sub_bytes(self, int n, unsigned char *state):
        """
        Substitutes each element of the state 'state' using the Rijndael S-box.
        Args:
            n: len(state)
            state: Pointer to char array
        """
        cdef int i

        for i in range(n):
            state[i] = self.s_box[state[i]]

    cdef void inv_sub_bytes(self, unsigned char *state):
        """
        Substitutes each element of the state 'state' using the Rijndael S-box.
        Args:
            state: Pointer to char array
        """
        for i in range(16):
            state[i] = self.inv_s_box[state[i]]

    @staticmethod
    cdef void shift_rows(unsigned char *state):
        """
        Shift rows of a given state
        Args:
            state: Pointer to char array
        """
        # Shift 1
        temp = state[1]
        state[1] = state[5]
        state[5] = state[9]
        state[9] = state[13]
        state[13] = temp

        # Shift 2
        temp = state[2]
        state[2] = state[10]
        state[10] = temp

        temp = state[6]
        state[6] = state[14]
        state[14] = temp

        # Shift 3
        temp = state[15]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = state[3]
        state[3] = temp

    @staticmethod
    cdef void inv_shift_rows(unsigned char *state):
        """
        Shift rows of a given state
        Args:
            state: Pointer to char array
        """
        cdef unsigned char temp
        # Shift 1
        temp = state[13]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = state[1]
        state[1] = temp

        # Shift 2
        temp = state[2]
        state[2] = state[10]
        state[10] = temp

        temp = state[6]
        state[6] = state[14]
        state[14] = temp

        # Shift 3
        temp = state[3]
        state[3] = state[7]
        state[7] = state[11]
        state[11] = state[15]
        state[15] = temp

    @staticmethod
    cdef void mix_columns(unsigned char *state):
        """
        Mix columns of a given state
        Args:
            state: Pointer to char array
        """
        cdef unsigned char c_2[4]
        cdef unsigned char c[4]
        cdef int i
        cdef int j

        for j in range(4):
            for i in range(4):
                c[i] = state[4*j + i]
                c_2[i] = state[4*j + i] << 1
                if c[i] & 0x80:
                    c_2[i] ^= 0x1b

            state[4*j] = c_2[0] ^ c_2[1] ^ c[1] ^ c[2] ^ c[3]
            state[4*j + 1] = c[0] ^ c_2[1] ^ c_2[2] ^ c[2] ^ c[3]
            state[4*j + 2] = c[0] ^ c[1] ^ c_2[2] ^ c_2[3] ^ c[3]
            state[4*j + 3] = c_2[0] ^ c[0] ^ c[1] ^ c[2] ^ c_2[3]

    @staticmethod
    cdef unsigned char rijndael_gf_mul(unsigned char x, unsigned char y):

        cdef unsigned char mask, res = 0
        cdef int i

        for i in range(8):
            res ^= -(y & 1) & x
            mask = -((x >> 7) & 1)
            x = (x << 1) ^(0x1b & mask)
            y >>= 1

        return res

    cdef void inv_mix_columns(self, unsigned char *state):
        """
        Inverse mix columns of a given state
        Args:
            state: 
        """
        cdef unsigned char c[4]
        cdef int i

        for j in range(4):
            for i in range(4):
                c[i] = state[4*j + i]

            state[4*j] = AES.rijndael_gf_mul(0xe, c[0]) ^ AES.rijndael_gf_mul(0xb, c[1]) ^ \
                       AES.rijndael_gf_mul(0xd, c[2]) ^ AES.rijndael_gf_mul(0x9, c[3])

            state[4*j + 1] = AES.rijndael_gf_mul(0x9, c[0]) ^ AES.rijndael_gf_mul(0xe, c[1]) ^ \
                       AES.rijndael_gf_mul(0xb, c[2]) ^ AES.rijndael_gf_mul(0xd, c[3])

            state[4*j + 2] = AES.rijndael_gf_mul(0xd, c[0]) ^ AES.rijndael_gf_mul(0x9, c[1]) ^ \
                       AES.rijndael_gf_mul(0xe, c[2]) ^ AES.rijndael_gf_mul(0xb, c[3])

            state[4*j + 3] = AES.rijndael_gf_mul(0xb, c[0]) ^ AES.rijndael_gf_mul(0xd, c[1]) ^ \
                       AES.rijndael_gf_mul(0x9, c[2]) ^ AES.rijndael_gf_mul(0xe, c[3])

    cdef void cipher_(self, unsigned char *state):
        """
        Cypher a given state
        Args:
            state: 
        """
        cdef int round_
        cdef unsigned char[16] temp

        self.add_round_key(state, 0)

        for round_ in range(1, self.nr):
            self.sub_bytes(16, state)
            AES.shift_rows(state)
            AES.mix_columns(state)
            self.add_round_key(state, round_)

        self.sub_bytes(16, state)
        AES.shift_rows(state)
        self.add_round_key(state, self.nr)

    def cipher(self, state):
        """
        Encrypts a given state
        Args:
            state (list(bytes (int))): State to encrypt. It must have at leats 16 elements.

        Returns:
            list(bytes (int))

        """
        cdef unsigned char[16] state_
        for i in range(16):
            state_[i] = state[i]

        self.cipher_(state_)
        return [state_[i] for i in range(16)]


    cdef void inv_cipher_(self, unsigned char *state):
        """
        Inverse cipher a given state
        Args:
            state: 
        """
        cdef int round_
        cdef unsigned char[16] temp

        self.add_round_key(state, self.nr)
        for round_ in range(self.nr - 1, 0, -1):
            AES.inv_shift_rows(state)
            self.inv_sub_bytes(state)
            self.add_round_key(state, round_)
            self.inv_mix_columns(state)

        AES.inv_shift_rows(state)
        self.inv_sub_bytes(state)
        self.add_round_key(state, 0)

    def inv_cipher(self, state):
        """
        Decrypts a given state
        Args:
            state (list(bytes)): Ciphered state to decrypt

        Returns:
            list(bytes (int))
        """
        cdef unsigned char[16] state_
        for i in range(16):
            state_[i] = state[i]

        self.inv_cipher_(state_)
        return [state_[i] for i in range(16)]


    cdef int process_file_(self, void (*f)(AES, unsigned char*),char* fname_r, char* fname_w):
        """
        Process a file (encrypts or decrypts a file)
        Args:
            f: processing function 
            fname_r: name of the reading file 
            fname_w: name of the writing file

        Returns:
            (int): 1 on sucess and -1 on failure i.e. opening a file
        """
        cdef FILE *fp_r
        cdef FILE *fp_w
        cdef unsigned char[1025] chunk
        cdef unsigned char[16] temp
        cdef int size, i, j

        fp_r = fopen(fname_r, "r")
        if not fp_r:
            print 'ERROR: Something went wrong when opening the reading file'
            return -1

        fp_w = fopen(fname_w, "w")
        if not fp_w:
            print 'ERROR: Something went wrong when opening the writing file'
            return -1

        while True:
            size = fread(chunk, 1, 1024, fp_r)
            if size <= 0:
                break
            for i in range(size//16):
                for j in range(16):
                    temp[j] = chunk[i*16 + j]
                f(self, temp)
                for j in range(16):
                    chunk[i*16 + j] = temp[j]
            if size%16 != 0:
                for j in range(16):
                    temp[j] = chunk[size//16 * 16 + j] if j < size%16 else 0
                f(self, temp)
                for j in range(16):
                    chunk[size//16 * 16 + j] = temp[j]
                size += 16 - size%16
            fwrite(chunk, 1, size, fp_w)
        fclose(fp_r)
        fclose(fp_w)

        return 1


    def process_file(self, fread, fwrite, cipher=True):
        """
        Process a file (encrypts it or decrypts it) and writes the result in an other one
        Args:
            fread (str): file to process
            fwrite (str): destination
            cipher (bool): if True it encrypts the file else it decrypts it
        """
        cdef char *fread_
        cdef char *fwrite_

        fread_ = <char *> malloc(len(fread))
        fwrite_ = <char *> malloc(len(fwrite))

        for i,c in enumerate(fread):
            fread_[i] = ord(c)
        for i,c in enumerate(fwrite):
            fwrite_[i] = ord(c)

        if cipher:
            return self.process_file_(self.cipher_, fread_, fwrite_)
        else:
            return self.process_file_(self.inv_cipher_, fread_, fwrite_)
