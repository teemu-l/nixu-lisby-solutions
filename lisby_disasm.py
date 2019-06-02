import sys

if len(sys.argv) == 2:
    filename = sys.argv[1]
else:
    print('usage: python lisby_disasm.py <inputfile>')
    exit()

with open(filename, 'rb') as f:
    # check file header
    magic = f.read(8)
    if magic != b'LISBY001':
        raise ValueError('Error, wrong file format.')

    # String table
    strings = []
    entry_count = int.from_bytes(f.read(8), byteorder='little', signed=True)
    print('Entries on strings table: %d' % entry_count)

    for i in range(entry_count):
        length = int.from_bytes(f.read(8), byteorder='little', signed=True)
        str_bytes = f.read(length)
        strings.append(str_bytes.decode("UTF-8"))

    # Symbol table
    symbols = []
    entry_count = int.from_bytes(f.read(8), byteorder='little', signed=True)
    print('Entries on symbols table: %d' % entry_count)

    for i in range(entry_count):
        sym_length = int.from_bytes(f.read(8), byteorder='little', signed=True)
        sym_bytes = f.read(sym_length)
        symbols.append(sym_bytes.decode("UTF-8"))

    print('Strings: ' + str(strings))
    print('Symbols: ' + str(symbols))

    tape_count = int.from_bytes(f.read(8), byteorder='little', signed=True)
    print('Tapes: %d' % tape_count)

    memonics = [
        'HLT', 'ADD', 'SUB', 'MUL', 'DIV', 'XOR', 'MOD', 'AND', 'OR',
        'INV', 'PUSHI', 'PUSHF', 'PUSHSTR', 'PUSHSY', 'PUSHSYRAW', 'PUSHTRUE',
        'PUSHFALSE', 'PUSHUNIT', 'PUSHCLOSURE', 'PUSHCONT', 'QUOTED', 'POP',
        'CALL', 'TAILCALL', 'RET', 'JT', 'JF', 'JMP', 'STORE', 'STORETOP',
        'EQ', 'NEQ', 'GT', 'GE', 'LT', 'LE', 'NOT', 'DECLARE', 'PRINT',
        'LIST', 'HEAD', 'TAIL', 'LISTCAT', 'EVAL', 'DUMP', 'NEWENV', 'DEPARTENV'
    ]

    # memonics with data
    data_memonics = [
        'PUSHI', 'PUSHF', 'PUSHSTR', 'PUSHSY', 'STORE', 'STORETOP',
        'PUSHCLOSURE', 'JT', 'JF', 'JMP', 'DECLARE', 'LIST', 'PUSHSYRAW',
        'QUOTED', 'PUSHCONT'
    ]

    # Disassemble tapes
    for tape in range(tape_count):
        read_count = 0

        length_of_tape = int.from_bytes(f.read(8), byteorder='little', signed=True)
        print('----------------------------------')
        print('Tape id: %d | Length: %d' % (tape, length_of_tape))

        while read_count < length_of_tape:
            offset = read_count
            opcode = int.from_bytes(f.read(1), byteorder='little')
            read_count += 1
            try:
                memonic = memonics[opcode]
            except IndexError:
                print('Unknown opcode: %d' % opcode)
                exit()

            if memonic in data_memonics:
                data = int.from_bytes(f.read(8), byteorder='little', signed=True)
                read_count += 8
                memonic += ' ' + hex(data) # + '  (' + str(data) + ')'
            print('%s  %s' %(hex(offset), memonic))

    magic2 = f.read(8)
    if magic2 != b'100YBSIL':
        raise ValueError('Error, wrong file ending.')
