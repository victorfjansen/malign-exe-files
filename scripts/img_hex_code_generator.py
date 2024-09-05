import os
import argparse
from PIL import Image
import math
import signal

# Custom exception for timeout
class TimeoutException(Exception):
    pass

# Timeout handler function
def timeout_handler(signum, frame):
    raise TimeoutException()

# Convert exe file to hex
def exe_to_hex(filepath):
    with open(filepath, 'rb') as file:
        return file.read().hex()

# Convert hex string to decimal values
def hex_to_decimal(hex_string):
    decimal_values = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    return decimal_values

# Calculate image dimensions based on data length
def calculate_dimensions(data_length):
    num_pixels = data_length // 3
    width = height = int(math.sqrt(num_pixels))
    
    while width * height < num_pixels:
        width += 1
        height = (num_pixels + width - 1) // width
    
    return width, height

# Create image from data, with timeout
def create_image_from_data(data, output_filepath):
    # Set up signal for timeout (10 seconds)
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(5)  # Set timeout to 10 seconds

    try:
        width, height = calculate_dimensions(len(data))
        
        expected_size = width * height * 3
        if len(data) < expected_size:
            data.extend([0] * (expected_size - len(data)))
        elif len(data) > expected_size:
            data = data[:expected_size]

        image_data = []
        for i in range(height):
            for j in range(width):
                index = (i * width + j) * 3
                if index + 3 <= len(data):
                    image_data.append((data[index], data[index+1], data[index+2]))

        image = Image.new('RGB', (width, height))
        image.putdata(image_data)
        image.save(output_filepath)
    
    except:
        raise TimeoutException(f"Image generation for {output_filepath} timed out.")
    finally:
        signal.alarm(5)  # Reset the alarm

# Process each directory
def process_directory(input_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for root, _, files in os.walk(input_dir):
        for filename in files:
            extension = os.path.splitext(filename)[1]
            if extension and "pack" not in extension and "rev" not in extension:
                exe_path = os.path.join(root, filename)
                hex_data = exe_to_hex(exe_path)
                decimal_data = hex_to_decimal(hex_data)
                
                top_folder = os.path.relpath(root, input_dir).split(os.sep)[0]
                output_directory = os.path.join(output_dir, top_folder)
                
                if not os.path.exists(output_directory):
                    os.makedirs(output_directory)
                
                output_file = os.path.join(output_directory, os.path.splitext(filename)[0] + '.png')
                
                try:
                    create_image_from_data(decimal_data, output_file)
                    print(f"Processed {filename} into image {output_file}")
                except:
                    print(f"Failed to process {filename}")
                    continue

def main():
    parser = argparse.ArgumentParser(description='Convert .exe files to images.')
    parser.add_argument('input_dir', type=str, help='Directory containing .exe files.')
    parser.add_argument('output_dir', type=str, help='Directory to save generated images.')
    
    args = parser.parse_args()
    
    process_directory(args.input_dir, args.output_dir)

if __name__ == '__main__':
    main()
