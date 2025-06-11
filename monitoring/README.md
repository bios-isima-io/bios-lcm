# Installing Metrics collector on nodes

## Setup
- checkout fluent-bit repo and generate deb files for fluent-bit
   ```
   cd packaging
   CMAKE_INSTALL_PREFIX=/usr FLB_TRACE=Off FLB_DISTRO=ubuntu/22.04 ./build.sh
   ```
- upload generated packages to artifact registry one by one
  ```
  gcloud artifacts apt upload packages --location=us --source=<path to generated deb file>
  ```
- create a metrics package
  ```
  cd $ROOT/tools/node-metrics
  rm build/*
  ../../scripts/packager/make-self.sh -d . -n fluentbit-self-install
  ls -larth build/fluentbit-self-install.bsx
  ```
- Upload it to GCS
  ```
  gsutil cp build/fluentbit-self-install.bsx gs://isima-builds
  ```
  

## How to use
- copy build/fluentbit-self-install.bsx to any machine
- login to the machine and run the file as follows
   ```
   export WEBHOOK_PATH=/integration/<tenant>/nodestats e.g /integration/isima/nodestats
   export DOMAIN_NAME=<domain of the cluster> e.g. load-1.tieredfractals.com
   export USER=<email address of user> e.g. observe_reader@isima.io
   export PASSWORD=<password for the above user>
   bash fluentbit-self-install.bsx
   ```
