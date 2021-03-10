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
Please consider the prerequisites in the section above before running the `docker-compose`
file.

```bash
docker-compose -f docker-compose.yml up -d
```
