.PHONY: all setup-python install-deps mnemonic-csv general-csv multilabel-csv matrix-probabilities eigen-vector hex-image deploy

# Default target
all: setup-python install-deps mnemonic-csv general-csv multilabel-csv matrix-probabilities eigen-vector hex-image

# Step to set up Python (requires Python 3.12 to be pre-installed)
setup-python:
	@echo "Setting up Python..."
	# Python version setup is typically done manually in Makefile, or assumed to be pre-installed

# Install dependencies
install-deps:
	python3 -m pip install --upgrade pip --break-system-packages
	pip install capstone pefile pillow networkx matplotlib scipy pandas numpy --break-system-packages

# Generate most common mnemonic codes CSV
mnemonic-csv:
	python3 ./scripts/most_common_mnemonic_csv_generator.py ./ ./outputs/malign_pe_files_most_common_mnemonic.csv

# Generate general mnemonic codes CSV
general-csv:
	python3 ./scripts/all_mnemonic_csv_generator.py ./ ./outputs/malign_pe_files_general_mnemonic.csv

# Generate multilabel mnemonic codes CSV
multilabel-csv:
	python3 ./scripts/multi_label_mnemonic_csv_generator.py ./ ./outputs/malign_pe_files_multilabel_mnemonic.csv

# Generate matrix probabilities
matrix-probabilities:
	python3 ./scripts/matrix_probability.py ./outputs/malign_pe_files_general_mnemonic.csv ./outputs/malware-graph-extraction/

# Generate dominant eigen vector
eigen-vector:
	python3 ./scripts/power_iteraction_embbed.py ./outputs/malware-graph-extraction/_matrix_probability/ ./outputs/malware-graph-extraction/_embeddings/

# Generate hexadecimal images from PE headers
hex-image:
	python3 ./scripts/img_hex_code_generator.py ./ ./outputs/malign_pe_files_images/

# Deploy to S3
deploy:
	# Replace with appropriate AWS CLI or SDK calls
	@echo "Deploying to S3..."
	# Example command with AWS CLI:
	# aws s3 sync ./outputs/ s3://$(AWS_S3_BUCKET) --acl public-read --delete
