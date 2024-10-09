import argparse
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import os
import csv
import sys

# Increase the CSV field size limit
csv.field_size_limit(sys.maxsize)

def parse_assembly(assembly_code):
    instructions = [line.strip() for line in assembly_code.split() if line.strip()]
    parsed_instructions = []
    
    for instruction in instructions:
        parts = instruction.split()
        op_code = parts[0]
        parsed_instructions.append(op_code)
    
    return parsed_instructions

def build_opcode_sequence_counts(opcodes):
    pair_count = defaultdict(lambda: defaultdict(int))
    
    for i in range(len(opcodes) - 1):
        current_op = opcodes[i]
        next_op = opcodes[i + 1]
        pair_count[current_op][next_op] += 1
    
    return pair_count

def build_cfg(opcodes, pair_count):
    G = nx.DiGraph()
    
    unique_opcodes = set(opcodes)
    for op_code in unique_opcodes:
        G.add_node(op_code)
    
    for op1 in pair_count:
        total = sum(pair_count[op1].values())

        for op2 in pair_count[op1]:
            weight = pair_count[op1][op2] / total if total > 0 else 0
            G.add_edge(op1, op2, weight=weight)
    
    return G

def build_matrix(G):
    nodes = list(G.nodes())
    node_index = {node: idx for idx, node in enumerate(nodes)}
    matrix = np.zeros((len(nodes), len(nodes)))
    
    for node1 in G.nodes():
        for node2 in G.nodes():
            if G.has_edge(node1, node2):
                matrix[node_index[node1], node_index[node2]] = G[node1][node2]['weight']
    
    return matrix

def plot_cfg(G, output_file):
    pos = nx.spring_layout(G) 

    plt.figure(figsize=(15, 10))
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color='lightblue', font_size=10, font_weight='bold', edge_color='gray')
    plt.title('Control Flow Graph')

    plt.savefig(output_file)
    plt.close()

def process_files(csv_file, output_dir):
    matrix_probability_dir = os.path.join(output_dir, '_matrix_probability')
    graphs_dir = os.path.join(output_dir, '_graphs_images')
    
    os.makedirs(matrix_probability_dir, exist_ok=True)
    os.makedirs(graphs_dir, exist_ok=True)
    
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        
        for row in reader:
            assembly_code = row['opcodes']
            file_name = row['file_name']
            
            opcodes = parse_assembly(assembly_code)
            pair_count = build_opcode_sequence_counts(opcodes)
            G = build_cfg(opcodes, pair_count)
            matrix = build_matrix(G)
            
            matrix_probability_file = os.path.join(matrix_probability_dir, f"{file_name}_matrix_probability.txt")
            plot_file = os.path.join(graphs_dir, f"{file_name}_cfg.png")
            
            np.savetxt(matrix_probability_file, matrix, fmt='%.2f', delimiter='\t', header='\t'.join(G.nodes()))
            print(f"Adjacency Matrix Probability with Weights saved to: {matrix_probability_file}")

            plot_cfg(G, plot_file)
            print(f"Control Flow Graph saved to: {plot_file}")

def main():
    parser = argparse.ArgumentParser(description="Generate control flow graphs from assembly code in a CSV file.")
    parser.add_argument("csv_file", help="CSV file path containing assembly code and file names.")
    parser.add_argument("output_dir", help="Directory path where output files will be saved.")
    
    args = parser.parse_args()
    
    process_files(args.csv_file, args.output_dir)

if __name__ == "__main__":
    main()
