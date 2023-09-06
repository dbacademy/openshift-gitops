## Objective
Implenet GitOps way of infrastructure provesioning using FluxCD

### Bootstraping for Sandbox cluster 

Get the repo PAT and owner details and set the environment variable according as below.
````
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxx
export GITHUB_USER=<your_repo_owner>
````
Now Run following bootstrap command as cluster admin.

````
flux bootstrap github \
  --owner=$GITHUB_USER \
  --repository=openshift-gitops \
  --branch=master \
  --path=./clusters/sandbox-net \
  --personal
````


### Unstall Flux system 

--keep-namespace is optional argument to not to delete namespace, in this case it is flux-system
```bash
flux uninstall --namespace=flux-system --keep-namespace
```

Following are importent commant to manage sources and kustomization controller. Replace the repo and kustomizaion name as per your environment.

````
flux get source git
flux get kustomization
oc get gitrepository
oc get kustomization
oc get gitrepository
flux reconcile source git icoe-mq-k8s-services
flux reconcile source git flux-system
oc get kustomization
flux reconcile kustomization bootstrap-mq-services-aro-prod
flux reconcile source git icoe-mq-k8s-services
flux reconcile kustomization bootstrap-mq-services-aro-prod
````
