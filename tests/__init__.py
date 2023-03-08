import pathlib

TEST_DIR = pathlib.Path(__file__).parent
TEST_DATA_DIR = TEST_DIR / "data"


def load_text_file(path: str, encoding: str = "utf-8") -> str:
    return (TEST_DATA_DIR / path).read_text(encoding=encoding)
