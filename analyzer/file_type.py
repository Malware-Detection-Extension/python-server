import magic

def get_file_type(file_path):
    try:
        return magic.from_file(file_path, mime=True)
    except Exception as e:
        return f"Unknown ({str(e)})"
