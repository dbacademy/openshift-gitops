#! /bin/bash
# set -e

# k8s cluster kubeconfig context where flux controllers are running
# icoe-westeu-private-aks-test
SOURCE_CLUSTER_CONTEXT=""

# nmaespace on source cluster where flux or argocd is running
SOURCE_CLUSTER_NAMESPACE=""

# namespace on destination cluster where service account will be created.
# if it's namespace mode, rolebinding will be created in this namespace
DEST_CLUSTER_NAMESPACE=""

# servicea account name on destination cluster
DEST_SERVICE_ACCOUNT=""

# destination k8s cluster kubeconfig context where flux controller will deplou workloads
# e.g., icoe-westeu-public-aks-sandbox
DEST_CLUSTER_CONTEXT=$2

# desination k8s cluster api server address 
# e.g., https://icoe-westeu-public-aks-sandbox-18721934.hcp.westeurope.azmk8s.io:443
DEST_CLUSTER_API_SERVER=""

# the name destination cluster
DEST_CLUSTER_NAME=""

# Secret name of the serviceaccount for remote clsuter
FLUX_KUBECONFIG_SECRET_NAME=""
ARGOCD_CLUSTER_SECRET_NAME=""

# base directory of this repository
REPO_BASE_DIR=""

# the type of the gitops tool that will be managing remote cluster
GITOPS_TYPE=""

log() {
    local level="${1}"; shift
    local prefix="$(date +"%Y-%m-%d %H:%M:%S") ${FUNCNAME[1]} ${level^^}"
    echo "${prefix}:" "$@"
}

# find the index of target's first occurrence in the string. function as string.indexOf("target")
# 
# $1 the string to search from
# $2 the target string to search
# it returns either -1 or the index. -1 indicates not found
get_first_index_of(){
# string to search index from
  local str=$1
  #  target string to search
  local target=$2
  # the returned index, -1 indicates notfound
  local index=0
  # no of chars that should be matched, that is the the lenth of the target
  local total_match=${#target}
  # index of the previous match, -1 indicates nonmatch, this is the inital value
  local pre_match_index=-1
  # no of chars that has matched the target, used for book keeping
  local match_no=0
  for (( i=0 ; i<=${#str}; i++ ));do
    c=${str:$i:1}
    # if we've found all chars, break
    if [ $match_no = $total_match ];then
    #   log "INFO" "we have a full match"
      index=$(expr $i - ${total_match} )
      echo $index
      break
    fi
    if [ -z $c ];then 
        # log "INFO" "run out of string, nothing found"
        echo -1
        break
    fi
    # if current character is not in the target, skip
    if ! [[ $target =~ $c ]]; then
        # log "INFO" "$c isn't matching ${target} skip"
        continue
    fi
    
    # first match
    if [ $pre_match_index = -1 ]; then
    # log "INFO" "$c matches ${target} consectively, for the 1st time"
      pre_match_index=$i
      match_no=$( expr $match_no + 1 )
      continue
    fi
    # it's match but if previous char wasn't a match, mark the index as pre_match_index and rest match_no to 1
    if [ ! $pre_match_index = $( expr $i - 1) ]; then
    # log "INFO" "the previous match index was $pre_match_index, the current match index is $i, it's not consective, start over"
      pre_match_index=$i
      match_no=1
      continue
    fi
    # now this is a consective match, increase no of consective matches by 1 and mark the index
    match_no=$( expr $match_no + 1 )
    pre_match_index=$i
    # log "INFO" "$c matches ${target} consectively, for the $match_no th time out of total ${total_match} "
  done
}

# dynamically get root path of this repo so that the script can be run from any folder
get_repo_base_dir() {
  # credit: https://stackoverflow.com/questions/59895/how-do-i-get-the-directory-where-a-bash-script-is-located-from-within-the-script
  # ref: https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html#index-BASH_005fSOURCE
  local current_running_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

  if [[  "$current_running_dir" =~ (/scripts)$ ]]; then
    index=$( get_first_index_of $current_running_dir "/scripts" )
    if [ ! $index = -1 ];then
      REPO_BASE_DIR=${current_running_dir:0:$index+2}
      return
    fi 
  # if script is run in the root folder of this repo
  # elif [[ "$current_running_dir" =~ (icoe-mq-k8s-services)$ ]]; then
  elif [[ "$current_running_dir" =~ (openshift-gitops)$ ]]; then
      REPO_BASE_DIR=$(pwd)
      return
  fi
  # this should not happen, but if it happens, we will safely exit
  log "ERROR" "can't find 'scripts' folder in current working dir ${current_running_dir}, run script inside the repo" 1>&2
  exit 1

}

# parse local kubeconfig file and output the mapping from context to apiserver to a json file
generate_contexts_file(){
  local output=$1

  get_contexts_error=$(python3 ${REPO_BASE_DIR}/scripts/get_contexts.py -o "${output}" 2>&1)
  if [ ! -z "${get_contexts_error}" ];then
    log "ERROR" "failed getting contexts: ${get_contexts_error}" 1>&2
    exit 1
  fi
}

# check if the kube context exists in the given contexts.json file. it returns api server if context exists, otherwise exit with error
check_cluster_context() {
  local contexts_file=$1
  local cluster_context=$2

  local context=$(echo ${cluster_context} | sed -E 's/(^[0-9]|#|\$|&|\*|@|\.|:|\/|-)/_/g' )
  # log "INFO" "using ${context} to check against all avaliable contexts"
  local api_server=$(cat ${contexts_file} | jq -r ."${context}" 2>&1)

  if [[ "${api_server}" =~ "null"|"error" ]]; then

    log "ERROR" "failed to lookup '${context}': ${api_server} " 1>&2
    log "INFO" "Below contexts are available. NOTE: [ sed -E 's/(^[0-9]|#|\$|&|\*|@|\.|:|\/|-)/_/g' ] has been applied to the context name"
    cat ${contexts_file} | jq .
    exit 1
  fi

}

# parse args from commandline. if mandatory arguments are not present, exit with error
parse_check_args(){
  while getopts ":h:t:s:d:r:k:m:" arg; do

    case $arg in
      h )
          cat <<EOF

  serectutil creates cluster credetials for ArgoCD and Flux to connect to remote cluster. The secret will be created in the same namespace as Flux and ArgoCD

  Usage: serectutil.sh [Options]

  Options:
   -t GITOPS_TYPE: Mandatory
      The type of the gitops tool that will be managing remote cluster. either 'flux' or 'argocd'

   -s SOURCE_NS/SOURCE_CLUSTER_CONTEXT: Mandatory
      kubectl context for kubeneretes cluster where flux or argocd controllers are running and target namespace. 
      Must be in format <SOURCE_NS/SOURCE_CLUSTER_CONTEXT>

   -d DEST_NS/DESTINATION_CLUSTER_CONTEXT: Mandatory
      kubectl context for destination kubeneretes cluster where flux/arogcd will deploy resources to the target namespace. 
      Must be in format <DEST_NS/DESTINATION_CLUSTER_CONTEXT> 

   -r DESTINATION_CLUSTER_ROLE: Mandatory
      k8s ClusterRole on destination flux and destination cluster that flux will use to deploy

   -m MANAGEMENT_MODE: Mandatory
      either 'cluster' or 'namespace', indicate if flux or argocd should manage cluster-level resources or namespace level resources
      - cluster: secret access will be based on ClusterRoleBinding
      - namespace: secret access will be based on RoleBinding on target namespace

   -k [DESTINATION_CLUSTER_NAME]: Optional
      Name of destination cluster, default to DESTINATION_CLUSTER_CONTEXT. it's used to construct the secret name.
      - Flux: the secret name will be 'DESTINATION_CLUSTER_NAME-kubeconfig'
      - Argocd: the secret name will be DESTINATION_CLUSTER_NAME
  
    
  e.g., serectutil.sh -t flux -s icoe-mq-services/aks-test -d icoe-mq-services/aks-prod -r flux -m cluster
  
  This will create a flux kubeconfig secret named 'aks-prod-kubeconfig' in 'icoe-mq-services' namespace on 'aks-test' cluster. 
  And the secret will have access to the 'aks-prod' as defined by ClusterRole 'flux'. 
  
  See reference below for more details on how it works

  Reference:
    Both flux and argocd manage remote cluster via Service Account on remote cluster. The Token and CA in the secret that assiciates with
    ServiceAccount will be used to authenticate with remote cluster

    1. Flux
      Flux uses kubeconfig secret as defined by Flux -> 
      https://fluxcd.io/flux/components/kustomize/kustomizations/#remote-clusterscluster-api
      https://fluxcd.io/flux/components/helm/helmreleases/#kubeconfig-reference
      
    2. ArgoCD
      ArgoCD uses Cluster Secret as defined by ArgoCD ->
      https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/#clusters

EOF
          exit 1
          ;;
      t )
          GITOPS_TYPE=${OPTARG}
          if [[ ! "${GITOPS_TYPE}" =~ ("flux"|"argocd") ]]; then
            log "ERROR" "gitops type must be either 'flux' or 'argocd'" 1>&2
            exit 1
          fi
          ;;
      s )
          source=${OPTARG}
          if [[ ! ${source}  =~ "/" ]];then
            log "ERROR" "source ${source} format incorrect, should be <namesapce>/<source_context>" 1>&2
            exit 1
          fi
          index=$( get_first_index_of ${source} "/" )
          SOURCE_CLUSTER_NAMESPACE=${source:0:index}
          len=$( expr ${#source} - ${index} - 1 )
          SOURCE_CLUSTER_CONTEXT=${source:index+1:${len}}
          ;;
      d )
          dest=${OPTARG} 
          if [[ ! ${dest}  =~ "/" ]];then
            log "ERROR" "destination ${dest} format incorrect, should be <namesapce>/<context>" 1>&2
            exit 1
          fi
          index=$( get_first_index_of ${dest} "/" )
          DEST_CLUSTER_NAMESPACE=${dest:0:index}
          len=$( expr ${#dest} - ${index} - 1 )
          DEST_CLUSTER_CONTEXT=${dest:index+1:${len}}
          ;;
      r )
          DEST_CLUSTER_ROLE=${OPTARG}
          ;;
      m )
          MANAGEMENT_MODE=${OPTARG}
          if [[ ! "${MANAGEMENT_MODE}" =~ ("cluster"|"namespace") ]]; then
            log "ERROR" "management mode must be either 'cluster' or 'namespace' " 1>&2
            exit 1
          fi
          ;;
      k )
          DEST_CLUSTER_NAME=${OPTARG}
          ;;
      * )
        log "ERROR" "unknown arg ${arg}" 1>&2
        exit 1
        ;;
    esac
  done

  if [[ ${SOURCE_CLUSTER_CONTEXT} = "" ]] \
      || [[  ${DEST_CLUSTER_CONTEXT} = "" ]] \
      || [[  ${DEST_CLUSTER_ROLE} = "" ]] \
      || [[  ${MANAGEMENT_MODE} = "" ]] \
      || [[  ${GITOPS_TYPE} = "" ]]; then
  
    log "ERROR" "madatory arguments missing, use option [-h help] to check usage " 1>&2
    exit 1
  fi
}

#  init variables 
# updated by dbiswas
# changed from mq-flux to ocp-flux and mq-argocd to ocp-argocd
init_vars(){

  if [[ ${GITOPS_TYPE} = "flux" ]]; then
    DEST_SERVICE_ACCOUNT=ocp-flux
  fi
  if [[ ${GITOPS_TYPE} = "argocd" ]]; then
    DEST_SERVICE_ACCOUNT=ocp-argocd
  fi
  
  # tmp folder to store context file
  tmp_contexts_file="${REPO_BASE_DIR}/contexts.json"
  # check contexts
  # generate temporary contexts json file
  generate_contexts_file $tmp_contexts_file
  # check destination cluster
  check_cluster_context $tmp_contexts_file $DEST_CLUSTER_CONTEXT
  # check if management cluster context exists
  check_cluster_context $tmp_contexts_file $SOURCE_CLUSTER_CONTEXT

  dest_context=$(echo ${DEST_CLUSTER_CONTEXT} | sed -E 's/(^[0-9]|#|\$|&|\*|@|\.|:|\/|-)/_/g' )
  api_server=$(cat ${tmp_contexts_file} | jq -r ."${dest_context}" 2>&1)
  DEST_CLUSTER_API_SERVER=${api_server}

  if [[ ${DEST_CLUSTER_NAME} = "" ]]; then
     DEST_CLUSTER_NAME=${DEST_CLUSTER_CONTEXT}
  fi
 
  # Secret name of the serviceaccount for remote clsuter
  if [[ ${FLUX_KUBECONFIG_SECRET_NAME} = "" ]];then
    FLUX_KUBECONFIG_SECRET_NAME=${DEST_CLUSTER_NAME}-kubeconfig
  fi 
  if [[ ${ARGOCD_CLUSTER_SECRET_NAME} = "" ]]; then
    ARGOCD_CLUSTER_SECRET_NAME=argocd-cluster-${DEST_CLUSTER_NAME}
  fi
  # tmp file for storing ca data
  TMP_KUBECONFIG_FILE_PATH=$(pwd)/value.yaml
  log_info="$(date +"%Y-%m-%d %H:%M:%S") init_vars: INFO"
  cat <<EOF
${log_info} vars:

    SOURCE_CLUSTER_CONTEXT = ${SOURCE_CLUSTER_CONTEXT}
    DEST_CLUSTER_CONTEXT = ${DEST_CLUSTER_CONTEXT}
    DEST_CLUSTER_ROLE = ${DEST_CLUSTER_ROLE}
    SOURCE_CLUSTER_NAMESPACE = ${SOURCE_CLUSTER_NAMESPACE}
    DEST_CLUSTER_NAMESPACE = ${DEST_CLUSTER_NAMESPACE}
    DEST_SERVICE_ACCOUNT = ${DEST_SERVICE_ACCOUNT}
    DEST_CLUSTER_API_SERVER = ${api_server}
    DEST_CLUSTER_NAME = ${DEST_CLUSTER_CONTEXT}
    FLUX_KUBECONFIG_SECRET_NAME = ${FLUX_KUBECONFIG_SECRET_NAME}
    ARGOCD_CLUSTER_SECRET_NAME = ${ARGOCD_CLUSTER_SECRET_NAME}

EOF
}

# basis for all, so we need to run it separately
check_cli_tools(){
  kubectl_exists=$(which kubectl 2>&1)
  if [ -z "$kubectl_exists" ]; then
    log "ERROR" "Kubectl isn't installed" 1>&2
    exit 1
  fi
  jq_exists=$(which jq 2>&1)
  if [ -z "$jq_exists" ]; then
    log "ERROR" "jq cli isn't installed" 1>&2
    exit 1
  fi
  python3_exists=$(which python3 3>&1)
  if [ -z "$python3_exists" ]; then
    log "ERROR" "Python3 isn't installed" 1>&2
    exit 1
  fi
  pip3_exists=$( which pip3 2>&1 )
  if [ -z "$pip3_exists" ]; then
    log "ERROR" "pip3 isn't installed" 1>&2
    exit 1
  fi
  
}

# pre_flight_check checks below
# 1. source context has admin access to source namespace
# 2. namespace mode, destination context has admin access to destination namespace
# 3. cluster mode, destination context has cluster-admin access and the clusterole exists
pre_flight_check(){

  log "INFO" "validating access on source ${SOURCE_CLUSTER_CONTEXT}"
  local res=$( kubectl config use ${SOURCE_CLUSTER_CONTEXT} 2>&1 )
  local can_get_source=$( kubectl get all -n ${SOURCE_CLUSTER_NAMESPACE} 2>&1)

  if [[ "${can_get_source}" =~ forbidden ]];then
    log "ERROR" "not admin on source cluster ${SOURCE_CLUSTER_CONTEXT}" 1>&2 
    exit 1
  fi

  log "INFO" "validating access on  destination ${DEST_CLUSTER_CONTEXT}"
  res=$( kubectl config use ${DEST_CLUSTER_CONTEXT} 2>&1 )

  if [[ ${MANAGEMENT_MODE} = "cluster" ]]; then

      is_cluster_admin=$( kubectl get node 2>&1)
      if [[ "${is_cluster_admin}" =~ forbidden ]];then
        log "ERROR" "if management node is 'cluster', ${DEST_CLUSTER_CONTEXT} must have cluster-admin access" 1>&2
        exit 1
      fi

      log "INFO" "validating clusterrole ${DEST_CLUSTER_ROLE} on ${DEST_CLUSTER_CONTEXT}"
      local clustrrole_exists=$(kubectl get clusterrole ${DEST_CLUSTER_ROLE})

      if [[ "${clustrrole_exists}" =~ "NotFound" ]];then
        log "ERROR" "ClusterRole ${DEST_CLUSTER_ROLE} not found on ${DEST_CLUSTER_CONTEXT}" 1>&2
        exit 1
      fi

  elif [[ ${MANAGEMENT_MODE} = "cluster" ]]; then
      local ns_admin=$( kubectl get all -n ${DEST_CLUSTER_NAMESPACE} 2>&1)
      if [[ "${ns_admin}" =~ forbidden ]];then
        log "ERROR" "if management node is 'namespace', ${DEST_CLUSTER_CONTEXT} must be namespace-admin" 1>&2
        exit 1
      fi
  fi
}

# create namespace on destination cluster
ensure_source_dest_ns() {
  # check namespace exists

  _ensure_ns ${SOURCE_CLUSTER_CONTEXT}  ${SOURCE_CLUSTER_NAMESPACE}
  _ensure_ns ${DEST_CLUSTER_CONTEXT}  ${DEST_CLUSTER_NAMESPACE}

}
_ensure_ns() {
  local context=$1
  local namespace=$2
  
  if [[ $# -ne 2 ]];then
    log "INFO" "not enough arguments"
    exist 1
  fi

  kubectl config use $context

# icoe_mq_exists changed ro ocp_ns_exists
#  local icoe_mq_exists=$(kubectl get ns ${namespace} 2>&1)
  local ocp_ns_exists=$(kubectl get ns ${namespace} 2>&1)  
  log "INFO" "making sure namespace ${namespace} exist on ${context}"

  if [[ "${ocp_ns_exists}" =~ NotFound ]];then
    log "INFO" "namespace ${namespace} doesn't exist on ${context}, creating it... ";
    kubectl create ns ${namespace};
  else
    log "INFO" "namespace ${namespace} exists on ${context}, skip creating... "
  fi
}

# create rbac on destination cluster
ensure_dest_rbac(){
  
  # create service account and cluster-role binding  on destination clsuter
  local sa_exists=$(kubectl get sa ${DEST_SERVICE_ACCOUNT} -n ${DEST_CLUSTER_NAMESPACE} 2>&1)
  if [[ "${sa_exists}" =~ "NotFound" ]];then
    log "INFO" "creating ServiceAccount ${DEST_CLUSTER_NAMESPACE}/${DEST_SERVICE_ACCOUNT} on ${DEST_CLUSTER_CONTEXT}"
    kubectl create sa ${DEST_SERVICE_ACCOUNT} -n ${DEST_CLUSTER_NAMESPACE}
  else
    log "INFO" "ServiceAccount ${DEST_CLUSTER_NAMESPACE}/${DEST_SERVICE_ACCOUNT} exists on ${DEST_CLUSTER_CONTEXT}, skip creating"
  fi

  local sa_secret_exists=$(kubectl get secrets ${DEST_SERVICE_ACCOUNT} -n ${DEST_CLUSTER_NAMESPACE} 2>&1)

  if [[ ${sa_secret_exists} =~ "NotFound" ]];then
    log "INFO" "creating ServiceAccount Secret ${DEST_CLUSTER_NAMESPACE}/${DEST_SERVICE_ACCOUNT} on ${DEST_CLUSTER_CONTEXT} "
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${DEST_SERVICE_ACCOUNT}
  namespace: ${DEST_CLUSTER_NAMESPACE}
  annotations:
    kubernetes.io/service-account.name: ${DEST_SERVICE_ACCOUNT}
type: kubernetes.io/service-account-token
EOF
  else
    log "INFO" "ServiceAccount secret ${DEST_CLUSTER_NAMESPACE}/${DEST_SERVICE_ACCOUNT} exists on ${DEST_CLUSTER_CONTEXT}, skip creating..."
  fi

  if [[ ${MANAGEMENT_MODE} = "cluster" ]];then
    _ensure_dest_cluterrolebinding
  elif  [[ ${MANAGEMENT_MODE} = "namespace" ]];then
    _ensure_dest_rolebinding
  fi
}

_ensure_dest_cluterrolebinding(){
  
  crb_exists=$(kubectl get clusterrolebinding ${DEST_SERVICE_ACCOUNT} -o name 2>&1)
  if [[ "${crb_exists}" =~ NotFound ]];then
    log "INFO" "creating ClusterRoleBinding ${DEST_SERVICE_ACCOUNT} on ${DEST_CLUSTER_CONTEXT}"
    kubectl create clusterrolebinding  ${DEST_SERVICE_ACCOUNT} \
    --clusterrole=${DEST_CLUSTER_ROLE} --serviceaccount=${DEST_CLUSTER_NAMESPACE}:${DEST_SERVICE_ACCOUNT}
  else
    log "INFO" "ClusterRoleBinding ${DEST_SERVICE_ACCOUNT} exists on ${DEST_CLUSTER_CONTEXT}. replacing it"
 
    local resut=$( _replace_dest_cluterrolebinding 2>&1 )
    if [[ "${resut}" =~ (invalid|error) ]]; then
      log "ERROR" "failed replacing ${DEST_CLUSTER_ROLE}: ${resut}" 1>&2
      exit 1
    fi
  fi

}

_replace_dest_cluterrolebinding() {

 kubectl replace -o name -f - <<EOF
  apiVersion: rbac.authorization.k8s.io/v1
  # This cluster role binding allows anyone in the "manager" group to read secrets in any namespace.
  kind: ClusterRoleBinding
  metadata:
    name: ${DEST_SERVICE_ACCOUNT}
  subjects:
  - kind: ServiceAccount
    name: ${DEST_SERVICE_ACCOUNT}
    namespace: ${DEST_CLUSTER_NAMESPACE}
  roleRef:
    kind: ClusterRole
    name: ${DEST_CLUSTER_ROLE}
    apiGroup: rbac.authorization.k8s.io
EOF

}

# creates a rolebinding on icoe services namespace for admin

_ensure_dest_rolebinding() {

  local crb_exists=$(kubectl get rolebinding ${DEST_SERVICE_ACCOUNT} -n ${DEST_CLUSTER_NAMESPACE} -o name 2>&1)
  if [[ "${crb_exists}" =~ NotFound ]];then
    log "INFO" "creating RoleBinding ${DEST_SERVICE_ACCOUNT} on ${DEST_CLUSTER_CONTEXT}"
    kubectl create rolebinding  ${DEST_SERVICE_ACCOUNT} \
    --clusterrole=${DEST_CLUSTER_ROLE} --serviceaccount=${DEST_CLUSTER_NAMESPACE}:${DEST_SERVICE_ACCOUNT} \
    -n ${DEST_CLUSTER_NAMESPACE}
  else
    log "INFO" "RoleBinding ${DEST_SERVICE_ACCOUNT} exists on ${DEST_CLUSTER_CONTEXT}. replacing it"

    resut=$( _replace_dest_rolebinding 2>&1 )
    if [[ "${resut}" =~ (invalid|error) ]]; then
      log "ERROR" "failed replacing ${DEST_CLUSTER_ROLE}: ${resut}" 1>&2
      exit 1
    fi
  fi
  
}
_replace_dest_rolebinding() {

  kubectl replace -o name -f - <<EOF
  apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    name: ${DEST_SERVICE_ACCOUNT}
    namespace: ${DEST_CLUSTER_NAMESPACE}
  subjects:
  - kind: ServiceAccount
    name: ${DEST_SERVICE_ACCOUNT}
    namespace: ${DEST_CLUSTER_NAMESPACE}
  roleRef:
    kind: ClusterRole
    name: ${DEST_CLUSTER_ROLE}
    apiGroup: rbac.authorization.k8s.io
EOF

}

extract_token_ca(){
  # exract ca certificate and token from destination cluster
  log "INFO" "extracting token and ca from ServiceAccount Secret ${DEST_CLUSTER_NAMESPACE}/${DEST_SERVICE_ACCOUNT} on ${DEST_CLUSTER_CONTEXT}"

  CA_DATA=$( kubectl get secret ${DEST_SERVICE_ACCOUNT} -n ${DEST_CLUSTER_NAMESPACE} -o jsonpath='{.data.ca\.crt}' )

  TOKEN_DATA=$(kubectl get secret ${DEST_SERVICE_ACCOUNT} -n ${DEST_CLUSTER_NAMESPACE} -o jsonpath='{.data.token}' | base64 -d)

}


ensure_secret() {
  log "INFO" "applying secret for ${GITOPS_TYPE}"
  if [[ ${GITOPS_TYPE} = "flux" ]];then
      ensure_flux_kubeconfig_secret
  fi

  if [[ ${GITOPS_TYPE} = "argocd" ]]; then
    ensure_argocd_cluster_secret
  fi
}

ensure_flux_kubeconfig_secret(){

  echo "
    apiVersion: v1
    kind: Config
    clusters:
    - name: ${DEST_CLUSTER_NAME}
      cluster:
        certificate-authority-data: ${CA_DATA}
        server: ${DEST_CLUSTER_API_SERVER}
    contexts:
    - name: ${DEST_CLUSTER_NAME}
      context:
        cluster: ${DEST_CLUSTER_NAME}
        user: ${DEST_SERVICE_ACCOUNT}
    current-context: ${DEST_CLUSTER_NAME}
    users:
    - name: ${DEST_SERVICE_ACCOUNT}
      user:
        token: ${TOKEN_DATA}
  " > ${TMP_KUBECONFIG_FILE_PATH}

  local kubeconfig_secret_exists=$(kubectl get secret ${FLUX_KUBECONFIG_SECRET_NAME} -n ${SOURCE_CLUSTER_NAMESPACE} 2>&1)

  if [[ "${kubeconfig_secret_exists}" =~ "NotFound" ]];then
    log "INFO" "creating flux kubeconfig Secret ${SOURCE_CLUSTER_NAMESPACE}/${FLUX_KUBECONFIG_SECRET_NAME} on ${SOURCE_CLUSTER_CONTEXT}"
    kubectl create secret generic ${FLUX_KUBECONFIG_SECRET_NAME} -n ${SOURCE_CLUSTER_NAMESPACE} --from-file="${TMP_KUBECONFIG_FILE_PATH}"

  else
    log "INFO" "flux kubeconfig Secret ${SOURCE_CLUSTER_NAMESPACE}/${FLUX_KUBECONFIG_SECRET_NAME} exists on ${SOURCE_CLUSTER_CONTEXT},replacing it"
    kubectl delete secret ${FLUX_KUBECONFIG_SECRET_NAME} -n ${SOURCE_CLUSTER_NAMESPACE}
    kubectl create secret generic ${FLUX_KUBECONFIG_SECRET_NAME} -n ${SOURCE_CLUSTER_NAMESPACE} --from-file="${TMP_KUBECONFIG_FILE_PATH}" 
  fi

}

# either create or replace argocd cluster secret
ensure_argocd_cluster_secret() {

  local argocd_secret_exists=$(kubectl get secret ${ARGOCD_CLUSTER_SECRET_NAME} -n ${SOURCE_CLUSTER_NAMESPACE} 2>&1)

  if [[ "${argocd_secret_exists}" =~ "NotFound" ]];then
    log "INFO" "creating Argocd cluster Secret ${SOURCE_CLUSTER_NAMESPACE}/${ARGOCD_CLUSTER_SECRET_NAME} on ${SOURCE_CLUSTER_CONTEXT}"
     kubectl create -o name -f - <<EOF
      apiVersion: v1
      kind: Secret
      metadata:
        name:  ${ARGOCD_CLUSTER_SECRET_NAME}
        namespace: ${SOURCE_CLUSTER_NAMESPACE}
        labels:
          argocd.argoproj.io/secret-type: cluster
      type: Opaque
      stringData:
        name: ${DEST_CLUSTER_NAME}
        namespace: ${DEST_CLUSTER_NAMESPACE}
        server: ${DEST_CLUSTER_API_SERVER}
        config: |
          {
            "bearerToken": "${TOKEN_DATA}",
            "tlsClientConfig": {
              "insecure": false,
              "caData": "${CA_DATA}"
            }
          }
EOF

  else
    log "INFO" "replacing Argocd cluster Secret ${SOURCE_CLUSTER_NAMESPACE}/${ARGOCD_CLUSTER_SECRET_NAME} on ${SOURCE_CLUSTER_CONTEXT}"
    local resut=$( _reaplce_argocd_cluster_secret 2>&1 )
    if [[ "${resut}" =~ invalid|error|fail ]];then
      log "ERROR" "failed to create secret: ${resut}" 1>&2
      exit
    fi
  fi

}

_reaplce_argocd_cluster_secret() {

  kubectl replace -o name -f - <<EOF
  apiVersion: v1
  kind: Secret
  metadata:
    name: ${ARGOCD_CLUSTER_SECRET_NAME}
    namespace: ${SOURCE_CLUSTER_NAMESPACE}
    labels:
      argocd.argoproj.io/secret-type: cluster
  type: Opaque
  stringData:
    name: ${DEST_CLUSTER_NAME}
    namespace: ${DEST_CLUSTER_NAMESPACE}
    server: ${DEST_CLUSTER_API_SERVER}
    config: |
      {
        "bearerToken": "${TOKEN_DATA}",
        "tlsClientConfig": {
          "insecure": false,
          "caData": "${CA_DATA}"
        }
      }
EOF
}

post_check(){
  # check kubeconfig file
  if [[ ${GITOPS_TYPE} = "flux" ]]; then
    kubectl config use ${DEST_CLUSTER_NAME} --kubeconfig=${TMP_KUBECONFIG_FILE_PATH}
    if [[ ${MANAGEMENT_MODE} = "cluster" ]];then
      local res=$( kubectl get nodes --kubeconfig=${TMP_KUBECONFIG_FILE_PATH} 2>&1 )
      if [[ ! ${res} =~ "forbidden" ]];then
        log "INFO" "flux secret ${FLUX_KUBECONFIG_SECRET_NAME} has cluster-admin access on ${DEST_CLUSTER_NAME}"
      fi
    fi
    if [[ ${MANAGEMENT_MODE} = "namespace" ]];then
      res=$( kubectl get all -n ${DEST_CLUSTER_NAMESPACE} 2>&1 )
      if [[ ! ${res} =~ "forbidden" ]];then
        log "INFO" "flux secret ${FLUX_KUBECONFIG_SECRET_NAME} has ns-admin to ${DEST_CLUSTER_NAMESPACE} on ${DEST_CLUSTER_NAME}"
      fi
    fi
  fi
}

clean_up(){
  if [ -f ${TMP_KUBECONFIG_FILE_PATH} ];then
    log "INFO" "tmp '${TMP_KUBECONFIG_FILE_PATH}' removed "
    rm ${TMP_KUBECONFIG_FILE_PATH}
  fi
  if [ -f ${tmp_contexts_file} ];then
    rm ${tmp_contexts_file}
    log "INFO" "tmp '${tmp_contexts_file}' removed "
  fi
}

# main function 
cat <<EOF

    ------------------------------------------ sanity checks and init ------------------------------------------
EOF
check_cli_tools
parse_check_args $@
get_repo_base_dir
init_vars $1 $2 $3
cat <<EOF

    ------------------------------------------ check context access ------------------------------------------
EOF
pre_flight_check
cat <<EOF

    ------------------------------------------ prepare rbac ------------------------------------------
EOF
ensure_source_dest_ns
ensure_dest_rbac
cat <<EOF

    ------------------------------------------ extract token create secrets ------------------------------------------
EOF
extract_token_ca
res=$( kubectl config use ${SOURCE_CLUSTER_CONTEXT} 2>&1 )
if [[ ${res} =~ "Switched to context" ]]; then
  log "INFO" "using context SOURCE_CLUSTER_CONTEXT=${SOURCE_CLUSTER_CONTEXT}"
else
  exit 1 
fi
ensure_secret
cat <<EOF

    ------------------------------------------ post checks and clenup ------------------------------------------
EOF
post_check
clean_up
