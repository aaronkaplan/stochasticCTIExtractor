
import uuid
import os

def save_string_to_custom_temp_file(input_string: str) -> str:
    # Generate a unique file name using UUID
    unique_filename = str(uuid.uuid4()) + ".txt"
    
    # Define a temporary directory (you can customize this path)
    temp_dir = "/tmp"
    
    # Full path to the temporary file
    temp_file_path = os.path.join(temp_dir, unique_filename)
    
    # Write the string to the temporary file
    with open(temp_file_path, "w") as f:
        f.write(input_string)
    
    return temp_file_path