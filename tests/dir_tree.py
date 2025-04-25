import os
import argparse
from pathlib import Path

def print_directory_tree(root_dir, prefix="", is_last=True, exclude_patterns=None, is_root=False):
    """
    Print a directory tree structure starting from root_dir.
    
    Args:
        root_dir (str): The root directory to start from
        prefix (str): Prefix to use for current line (used for recursion)
        is_last (bool): Is this the last item in the current directory
        exclude_patterns (list): List of patterns to exclude from the tree
        is_root (bool): Whether this is the root directory
    """
    if exclude_patterns is None:
        exclude_patterns = []
        
    # Define the branch characters
    branch = "" if is_root else "└── " if is_last else "├── "
    
    # Get directory name
    dir_name = os.path.basename(root_dir)
    
    # Print current directory with appropriate prefix
    print(f"{prefix}{branch}{dir_name}/")
    
    # Update prefix for children
    child_prefix = prefix
    if not is_root:
        child_prefix = prefix + ("    " if is_last else "│   ")
    
    # Get list of all items in the directory
    try:
        items = sorted(os.listdir(root_dir))
        # Filter out excluded patterns
        if exclude_patterns:
            for pattern in exclude_patterns:
                items = [item for item in items if pattern not in item]
        
        # Process directories first, then files
        directories = [item for item in items if os.path.isdir(os.path.join(root_dir, item))]
        files = [item for item in items if os.path.isfile(os.path.join(root_dir, item))]
        
        # Process directories recursively
        for i, item in enumerate(directories):
            path = os.path.join(root_dir, item)
            print_directory_tree(path, child_prefix, i == len(directories) - 1 and len(files) == 0, exclude_patterns)
        
        # Process files
        for i, item in enumerate(files):
            is_last_file = (i == len(files) - 1)
            file_branch = "└── " if is_last_file else "├── "
            print(f"{child_prefix}{file_branch}{item}")
            
    except PermissionError:
        print(f"{child_prefix}└── [Permission Denied]")
    except Exception as e:
        print(f"{child_prefix}└── [Error: {str(e)}]")

def main():
    root_dir = os.path.join("..", "frontend")
    exclude = ["__pycache__", "log", "test", "requirements", "node_modules", ".json"]
    
    # Convert to absolute path
    root_dir = os.path.abspath(root_dir)
    
    # Print header
    print(f"Directory Tree for: {root_dir}")
    print()
    
    # Start recursive printing
    print_directory_tree(root_dir, exclude_patterns=exclude, is_root=True)

if __name__ == "__main__":
    main()