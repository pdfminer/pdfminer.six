import os


def absolute_sample_path(relative_sample_path):
    sample_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '../samples'))
    sample_file = os.path.join(sample_dir, relative_sample_path)
    return sample_file
