import os
import shutil


def file_name_no_ext(path: str) -> str:
    return os.path.splitext(path)[0]


def preprocess(dir_path: str) -> None:
    """
    If the sens_http_flows.json/xml does not have the corresponding png, del it.
    :param dir_path:
    """

    def del_file(ext: str):
        path = os.path.join(root, base_name + ext)
        if os.path.exists(path):
            os.remove(path)
            print('rm %s', path)

    for root, dirs, files in os.walk(dir_path):
        for d in dirs:
            d = os.path.join(root, d)
            if not any(fname.endswith('.png') for fname in os.listdir(d)):
                shutil.rmtree(d)
                print('rm %s', d)
        for file_name in files:
            if not file_name.endswith('.xml'):
                continue
            base_name = file_name_no_ext(os.path.join(root, file_name))
            if os.path.exists(os.path.join(root, base_name + '.png')):
                continue
            del_file('.xml')
            del_file('.json')
            del_file('.pcap')
            del_file('_sens_http_flows.json')


preprocess('F:/FlowIntent/Location/0/test')


