import argparse
import pandas as pd
import numpy as np
import os
import sys
from collections import Counter
from itertools import islice
import matplotlib.pyplot as plt
from multiprocessing import Pool, cpu_count
import logging

# Removed: csv.field_size_limit(sys.maxsize)

def parse_assembly(assembly_code):
    """
    Parse assembly code into a list of opcodes.
    """
    # Split by any whitespace and filter out empty strings
    return [opcode.strip() for opcode in assembly_code.split() if opcode.strip()]

def build_opcode_sequence_counts(opcodes):
    """
    Count consecutive opcode pairs.
    """
    # Create pairs using zip and count them using Counter
    pairs = zip(opcodes, islice(opcodes, 1, None))
    return Counter(pairs)

def build_cfg(opcodes, pair_counts):
    """
    Build the Control Flow Graph (CFG) represented as an adjacency matrix.
    """
    # Extract unique opcodes
    unique_opcodes = list(set(opcodes))
    opcode_to_idx = {opcode: idx for idx, opcode in enumerate(unique_opcodes)}
    num_opcodes = len(unique_opcodes)

    # Initialize adjacency matrix
    matrix = np.zeros((num_opcodes, num_opcodes), dtype=np.float32)

    # Populate the matrix with transition counts
    for (op1, op2), count in pair_counts.items():
        idx1 = opcode_to_idx[op1]
        idx2 = opcode_to_idx[op2]
        matrix[idx1, idx2] += count

    # Normalize the matrix to get probabilities
    row_sums = matrix.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1  # Prevent division by zero
    matrix = matrix / row_sums

    return unique_opcodes, matrix

def plot_cfg(unique_opcodes, matrix, output_file):
    """
    Plot the Control Flow Graph (CFG) and save it as an image.
    """
    import networkx as nx  # Imported here to avoid global dependency if plotting is skipped

    G = nx.DiGraph()
    G.add_nodes_from(unique_opcodes)

    # Add edges with weights
    rows, cols = np.where(matrix > 0)
    for i, j in zip(rows, cols):
        weight = matrix[i, j]
        G.add_edge(unique_opcodes[i], unique_opcodes[j], weight=weight)

    # Use a faster layout algorithm with limited iterations
    pos = nx.spring_layout(G, k=0.15, iterations=20)

    plt.figure(figsize=(10, 8))
    nx.draw_networkx_nodes(G, pos, node_size=500, node_color='lightblue')
    nx.draw_networkx_edges(G, pos, alpha=0.5)
    nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold')

    plt.title('Control Flow Graph')
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(output_file, bbox_inches='tight', dpi=150)
    plt.close()

def process_row(args):
    """
    Process a single row from the CSV: parse opcodes, build CFG, save matrix and plot.
    """
    assembly_code, file_name, matrix_dir, graphs_dir = args

    opcodes = parse_assembly(assembly_code)
    if len(opcodes) < 2:
        return f"Skipped {file_name}: not enough opcodes."

    pair_counts = build_opcode_sequence_counts(opcodes)
    unique_opcodes, matrix = build_cfg(opcodes, pair_counts)

    # Save the adjacency matrix with headers
    matrix_file = os.path.join(matrix_dir, f"{file_name}_matrix_probability.txt")
    header = '\t'.join(unique_opcodes)
    np.savetxt(matrix_file, matrix, fmt='%.4f', delimiter='\t', header=header, comments='')

    # Plot and save the CFG
    plot_file = os.path.join(graphs_dir, f"{file_name}_cfg.png")
    plot_cfg(unique_opcodes, matrix, plot_file)

    return f"Processed {file_name}"

def process_files(csv_file, output_dir):
    """
    Read the CSV file and process each row in parallel.
    """
    # Set up output directories
    matrix_dir = os.path.join(output_dir, '_matrix_probability')
    graphs_dir = os.path.join(output_dir, '_graphs_images')
    os.makedirs(matrix_dir, exist_ok=True)
    os.makedirs(graphs_dir, exist_ok=True)

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Read CSV using pandas for faster I/O
    try:
        df = pd.read_csv(csv_file, usecols=['opcodes', 'file_name'], engine='c')
    except Exception as e:
        logging.error(f"Error reading CSV file: {e}")
        sys.exit(1)

    # Prepare arguments for multiprocessing
    args_list = [
        (row.opcodes, row.file_name, matrix_dir, graphs_dir)
        for row in df.itertuples(index=False)
    ]

    # Set up multiprocessing pool
    num_workers = max(1, cpu_count() - 1)  # Reserve one CPU
    with Pool(processes=num_workers) as pool:
        for result in pool.imap_unordered(process_row, args_list):
            logging.info(result)

def main():
    """
    Parse command-line arguments and initiate processing.
    """
    parser = argparse.ArgumentParser(description="Generate control flow graphs from assembly code in a CSV file.")
    parser.add_argument("csv_file", help="Path to the CSV file containing 'opcodes' and 'file_name' columns.")
    parser.add_argument("output_dir", help="Directory where output matrices and graphs will be saved.")

    args = parser.parse_args()

    if not os.path.isfile(args.csv_file):
        print(f"CSV file not found: {args.csv_file}")
        sys.exit(1)

    process_files(args.csv_file, args.output_dir)

if __name__ == "__main__":
        main()
