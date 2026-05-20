# Azimuth — HPC/AIOps Evaluation Deployment Playbook

Ansible playbook to deploy [Azimuth](https://github.com/azimuth-cloud/azimuth) self-service
portal onto an existing Kubernetes cluster. For evaluation and exploration only — **Azimuth
requires an OpenStack backend to provision real cloud resources.**

## What is Azimuth?

Azimuth is a self-service portal developed for HPC and AI/ML use cases. It provides a simplified
interface for provisioning complex platforms including:
- Single-machine workstations with web-based console + desktop
- [Slurm](https://slurm.schedmd.com/) HPC clusters
- [JupyterHub](https://jupyter.org/hub) for interactive computing
- Kubernetes clusters via [Cluster API](https://cluster-api.sigs.k8s.io/)

Azimuth is designed for OpenStack clouds. Without OpenStack, the UI starts but shows no
resources. This playbook deploys it for UI exploration.

## Playbook

`playbooks/10_deploy_azimuth.yml`

## Architecture

```
  +-------------------+     +------------------------+
  |  User Browser     |---->|  NodePort 30090        |
  |                   |     |  (any k8s node)        |
  +-------------------+     +----------+-------------+
                                       |
                            +----------v-------------+
                            | Azimuth UI pod         |
                            |  /                     |
                            +----------+-------------+
                                       |
                            +----------v-------------+
                            | Azimuth API pod        |
                            |  (OpenStack provider)  |
                            +----------+-------------+
                                       |
                            +----------v-------------+
                            |  OpenStack (required)  |
                            |  Keystone / Nova etc.  |
                            +------------------------+
```

## Prerequisites

- Kubernetes cluster already running (e.g., the one deployed by playbooks 01-09)
- Helm 3 installed (playbook 06)
- Node with sufficient spare capacity (~800 Mi for Azimuth pods)

## Deployment

From the WSL control node:

```bash
cd /mnt/c/Users/kkgag/k8s_cluster
ansible-playbook -i inventory.ini playbooks/10_deploy_azimuth.yml
```

## Access

After deployment, access the Azimuth UI at:
```
http://<any-k8s-node-ip>:30090
```

## Important Caveats

| Limitation | Explanation |
|---|---|
| **No OpenStack** | Azimuth's primary value is managing OpenStack resources. Without it, the portal starts but cannot provision compute, networking, or storage. |
| **Null provider** | We configure Azimuth with a stub OpenStack auth URL. The UI will render but project lists will be empty. |
| **debug: true** | Debug mode is enabled for evaluation. Disable in production. |
| **secretKey** | This is a placeholder. Change it if you keep the deployment. |
| **apps/clusters/kubernetes tags** | All disabled in values. Enable only if you have the corresponding backends (e.g., AWX, CAPI). |

## For Real HPC Workloads

Azimuth alone does not provide HPC software. It manages the **lifecycle** of HPC resources.
The actual HPC stack is provisioned by Azimuth appliances/templates:

| Appliance | What it deploys |
|---|---|
| Slurm | HPC job scheduler cluster |
| JupyterHub | Multi-user notebook environment |
| Kubernetes (CAPI) | Managed k8s for AI/ML workloads |
| RStudio | Statistical computing |
| Remote Desktop | Web-based Linux desktop |

These appliances run as VMs or containers *on the underlying cloud* (e.g., OpenStack).

## If You Have OpenStack

To make this playbook functional, replace the null auth config with real OpenStack credentials:

```yaml
settings:
  secretKey: "your-actual-django-secret"
  debug: false

authentication:
  type: openstack
  openstack:
    authUrl: "https://your-openstack:5000/v3"
    projectName: "your-project"
    internalProjectName: "internal"
    internalProjectDomain: "Default"

# Optional: Enable Cluster API for Kubernetes provisioning
# Requires an existing management cluster with CAPI providers
```

## Resources & Links

- Azimuth source: https://github.com/azimuth-cloud/azimuth
- Config docs: https://azimuth-config.readthedocs.io/
- User docs: https://azimuth-cloud.github.io/azimuth-user-docs/
- [Azimuth at OpenInfra Summit Berlin 2022](https://www.youtube.com/watch?v=FRbpI7ZsvMw)
