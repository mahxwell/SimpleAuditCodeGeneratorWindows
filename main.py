import sys
import xls_parser as xls


if __name__ == '__main__':
    if len(sys.argv) >= 1:
        path_to_file = sys.argv[1]
        xls.read_xlsx(path_to_file)
        print("File Written")
    else:
        print("Error : Missing Arguments")
