PYTHON3 := $(shell python3 --version)

run:
ifdef PYTHON3
	python3 ./scripts/most_common_mnemonic_csv_generator.py  ./ ./outputs/malign_pe_files_most_common_mnemonic.csv
	python3 ./scripts/all_mnemonic_csv_generator.py  ./ ./outputs/malign_pe_files_general_mnemonic.csv
	python3 ./scripts/multi_label_mnemonic_csv_generator.py  ./ ./outputs/malign_pe_files_multilabel_mnemonic.csv
	python3 ./scripts/matrix_probability.py ./outputs/malign_pe_files_general_mnemonic.csv ./outputs/malware-graph-extraction/
	python3 ./scripts/power_iteraction_embbed.py ./outputs/malware-graph-extraction/_matrix_probability/ ./outputs/malware-graph-extraction/_embeddings/
	python3 ./scripts/img_hex_code_generator.py ./ ./outputs/malign_pe_files_images/
else 
	python3 ./scripts/most_common_mnemonic_csv_generator.py  ./ ./outputs/malign_pe_files_most_common_mnemonic.csv
	python3 ./scripts/all_mnemonic_csv_generator.py  ./ ./outputs/malign_pe_files_general_mnemonic.csv
	python3 ./scripts/multi_label_mnemonic_csv_generator.py  ./ ./outputs/malign_pe_files_multilabel_mnemonic.csv
	python3 ./scripts/matrix_probability.py ./outputs/malign_pe_files_general_mnemonic.csv ./outputs/malware-graph-extraction/
	python3 ./scripts/power_iteraction_embbed.py ./outputs/malware-graph-extraction/_matrix_probability/ ./outputs/malware-graph-extraction/_embeddings/
	python3 ./scripts/img_hex_code_generator.py ./ ./outputs/malign_pe_files_images/
endif