## Introduction
The project automates the daily-basis vulnerability scan currently provided by
the [Friendly Probing Suite](https://gitlab.developers.cam.ac.uk/uis/infra/probing).
It interacts with the Greenbone Vulnerability Management system to create and manage
the different modules and processes responsible for the scanning.

The implemented algorithm is inspired from the finite-state machine model; it assigns
a state to each object involved in the scan and defines the actions that will be
applied to it in order to advance the whole process.

## How it works (WIP)

## Requirements
To test the GMP client developed in this project, a GVM daemon should be running.
You can deploy the GVM components by following the instructions in
https://gitlab.developers.cam.ac.uk/uis/infra/gvm-deployment. The client will
then be able to access the GVM daemon on port `9390`.

You may want to review [config.ini](./config.ini) to adjust the default configuration
according to your environment. 

The hosts that will be scanned can either be specified in 
[data/hosts.csv](./data/hosts.csv) or retrieved from the Probing DB.

The following secrets are needed to access the GVM daemon and the Probing DB
and should be provided as environment variables.
```env
export GMP_USERNAME=foo
export GMP_PASSWORD=bar
export PG_USERNAME=qux
export PG_PASSWORD=quux
```

## Development
To run the `docker-compose` file, please consider the prerequisites in the section above.

```bash
docker-compose -f docker-compose.yml up -d
```

## Kubernetes deployment
To run the GMP client in a k8s cluster, follow these instructions:

1. Create a k8s secret, `probing-db`, for the Probing DB credentials.
```bash
kubectl create secret generic probing-db --from-literal=host=pg_host
--from-literal=username=foo --from-literal=password=bar -n gvm
```
2. Create a k8s secret, `gmp-client`, for the GVMd credentials.
```bash
kubectl create secret generic gmp-client --from-literal=username=foo
--from-literal=password=bar -n gvm
```
3. Create a k8s configmap, `gmp-client`, for the GMP client config.
```bash
kubectl create cm gmp-client --from-file=config.ini=./config.ini -n gvm
```

4. Make sure a persistent Volume Claim, `data-volume`,  is available for GMP client
to access GVMd certs and store its data.

4. Create the `gmp-client` k8s Deployment.
```bash
kubectl apply -f k8s/gmp-client-deployment.yaml
```
