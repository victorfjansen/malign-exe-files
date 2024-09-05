from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import os
import csv
from collections import Counter
import pefile

mnemonic_counter = Counter()

def disassemble_file(file_path):
    with open(file_path, "rb") as f:
        code = f.read()

    pe = pefile.PE(file_path)

    offset = False
    for section in pe.sections:
        if section.Name == b'.text\x00\x00\x00':
            offset = section.VirtualAddress
            codePtr = section.PointerToRawData
            codeEndPtr = codePtr + section.SizeOfRawData
            break
    
    if not offset or not codePtr or not codeEndPtr:
        return []

    code = pe.get_memory_mapped_image()[codePtr:codeEndPtr]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    instructions = []
    
    for instruction in md.disasm(code, offset):  
        mnemonic_counter[instruction.mnemonic] += 1
        instructions.append(instruction)

    filtered_disassembly = []
    for instruction in instructions:
            filtered_disassembly.append(f"{instruction.mnemonic}\t{instruction.op_str}")
    
    return filtered_disassembly

def get_locally_most_common_sequences(disassembly):
    filtered_disassembly = [] 
    for instruction in disassembly:
        instruction_mnemonic = instruction.split("\t")[0]
        if any(item[0] == instruction_mnemonic for item in mnemonic_counter.most_common(31)):
            filtered_disassembly.append(instruction_mnemonic)
    
    return filtered_disassembly

def process_directory(input_directory, csv_output_path):
    # Open the CSV file for writing
    with open(csv_output_path, "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["type", "opcodes", "file_name"])  # Write CSV header with the new column

        # Walk through the directory tree
        for root, _, files in os.walk(input_directory):
            for filename in files:
                if os.path.splitext(filename)[1]:
                    input_path = os.path.join(root, filename)
                    
                    try:
                        print(f"Processing {filename}...")
                        disassembled_code = disassemble_file(input_path)
                        most_common_opcodes = get_locally_most_common_sequences(disassembled_code)
                        opcode_sequence = " ".join(most_common_opcodes)
                    except:
                        continue
                    
                    # Extract the top-level directory name
                    top_folder = os.path.relpath(root, input_directory).split(os.sep)[0]
                    
                    # Write the row to the CSV with the top-level folder as the label and include the file name
                    if opcode_sequence:
                        csvwriter.writerow([top_folder, opcode_sequence, filename])
                    print(f"CSV row added for {filename} with label '{top_folder}'")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python disassemble.py <input_directory> <csv_output_path>")
        sys.exit(1)

    input_dir = sys.argv[1]
    csv_output_path = sys.argv[2]

    process_directory(input_dir, csv_output_path)
