import yaml
import json
import sys
import os
import argparse
import subprocess
import traceback
import re

def _init_cmd_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog='create contexts file')
    parser.add_argument("-o","--output",
                        dest="output",
                        help="absolute file path for output",
                        nargs=1,
                        required=True)
    return parser.parse_args()

def get_kube_folder():
    home = os.path.expanduser("~")
    kubeconfig_folder = os.path.join(home,".kube/config")
    if os.path.exists(kubeconfig_folder):
        return kubeconfig_folder
    if os.getenv("KUBECONFIG") != "":
        return os.getenv("KUBECONFIG")
    
    return ""

def get_all_contexts():
    """
    returns a dict containing context name and clsuter api server address
    """
    kubeconfig = get_kube_folder()
    if kubeconfig == "":
        print("error: kubeconfig not found",file=sys.stderr)
        os._exit(1)
    # dic stores the mapping from context to api server
    context_to_server = {}
    with open(kubeconfig,'r') as kfile:
       kube = yaml.safe_load(kfile)
       clusters = kube['clusters']
       kube_contexts = kube['contexts']
       # dict stores the mapping from cluster name to api-server
       cluster_map ={}
       for cluster in clusters:
           cluster_map[cluster['name']]=cluster['cluster']['server']
           
       for ctx in kube_contexts:
           # replace special chars so to work with jq    
           name = re.sub('^[0-9]|#|\$|&|\*|@|\.|:|\/|-','_',str(ctx['name']))
           context_to_server[name]=cluster_map[ctx['context']['cluster']]
           
    return context_to_server

def _ensure_packages():
    """
    make sure dependencies are installed
    
    """
    pip_list = os.popen('pip3 list')
    modules_stream = pip_list.readlines()
    # packages this function needs
    pakcages={'ruamel.yaml','pyaml'}
    for module in modules_stream:
        if len(pakcages) == 0:
            return
        pakcage = module.split(" ")[0].strip()
        if pakcage in pakcages:
            pakcages.remove(pakcage)
    
    for k in  pakcages:
        install_cmd = ["pip3","install",k]
        out=subprocess.run(install_cmd,capture_output=True)
        
        if len(out.stderr) != 0:
            raise ValueError("error installing packages: %s. command:", str(out.stderr))
def main():
    args = _init_cmd_args()
    outputs = args.output
    try:
        _ensure_packages()
        contexts = get_all_contexts()
        with open(outputs[0],'w') as ctx:
            json.dump(contexts,ctx)
    except Exception as e:
        print("error generating contexts: ",traceback.print_exception(e))
if __name__=="__main__":
    main()