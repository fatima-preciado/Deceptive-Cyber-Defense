#!/bin/bash
docker run -d \
  --name node_exporter \
  --restart=always \
  --net=host \
  quay.io/prometheus/node-exporter
