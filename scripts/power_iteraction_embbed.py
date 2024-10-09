import numpy as np
import sys
import os

def load_matrix(file_path):
    W = np.loadtxt(file_path, delimiter='\t', skiprows=1)
    return W

def power_iteration(W, v0=None, tolerance=1e-10, max_iterations=1000):
    if v0 is None:
        v0 = np.random.rand(W.shape[1])

    v = v0
    delta = float('inf')
    iteraction = 0

    while delta > tolerance and iteraction < max_iterations:
        v_next = np.dot(W, v)
        v_next = v_next / np.linalg.norm(v_next, ord=1) 
        delta = np.linalg.norm(v_next - v, ord=1) 
        v = v_next
        iteraction += 1
    
    return v, iteraction

def process_directory(input_directory, output_directory):
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    for filename in os.listdir(input_directory):
        if filename.endswith('.txt'):
            input_file_path = os.path.join(input_directory, filename)
            output_file_path = os.path.join(output_directory, filename.replace('.txt', '_embedding.txt'))
            print(f"Processing file: {filename}")
            try:
                W = load_matrix(input_file_path)
                dominant_vector, iterations = power_iteration(W)
                
                np.savetxt(output_file_path, dominant_vector, fmt='%.6f', header='Dominant Eigenvector', comments='')
                print(f"Results saved to {output_file_path}")
            except Exception as e:
                print(f"Error processing file {filename}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <input_directory_path> <output_directory_path>")
        sys.exit(1)
    
    input_directory = sys.argv[1]
    output_directory = sys.argv[2]

    if not os.path.isdir(input_directory):
        print("Provided input path is not a directory.")
        sys.exit(1)

    process_directory(input_directory, output_directory)
