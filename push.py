import os
import subprocess
import shutil


# Path to the root directory containing the virus categories
root_dir = "./"
# The GitHub repository URL (HTTPS or SSH)
repo_url = "https://github.com/your-username/your-repo.git"

# Function to upload files in batches of 99
def upload_batch(files, batch_num):
    for file in files:
        relative_path = os.path.relpath(file, root_dir)
        # Create necessary directories inside the repo
        destination_dir = os.path.join(os.getcwd(), os.path.dirname(relative_path))
        if not os.path.exists(destination_dir):
            os.makedirs(destination_dir)

        # Copy the file to the repo structure
        shutil.copy2(file, os.path.join(destination_dir, os.path.basename(file)))

    # Add files to Git and commit
    subprocess.run(["git", "add", "."])
    commit_message = f"Add batch {batch_num} of virus files"
    subprocess.run(["git", "commit", "-m", commit_message])

    # Push the commit to GitHub
    subprocess.run(["git", "push", "origin", "main"])

# Collect all files from the directories
all_files = []
for dirpath, _, filenames in os.walk(root_dir):
    for filename in filenames:
        all_files.append(os.path.join(dirpath, filename))

# Upload files in batches of 99
batch_size = 99
for i in range(0, len(all_files), batch_size):
    batch_files = all_files[i:i + batch_size]
    batch_num = (i // batch_size) + 1
    upload_batch(batch_files, batch_num)

print("All files uploaded successfully.")
