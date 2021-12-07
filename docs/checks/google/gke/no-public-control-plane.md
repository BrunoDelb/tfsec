---
title: no-public-control-plane
---

### Explanation

The GKE control plane is exposed to the public internet by default. 

### Possible Impact
GKE control plane exposed to public internet

### Suggested Resolution
Use private nodes and master authorised networks to prevent exposure


### Insecure Example

The following example will fail the google-gke-no-public-control-plane check.

```terraform

resource "google_service_account" "default" {
  account_id   = "service-account-id"
  display_name = "Service Account"
}

resource "google_container_cluster" "primary" {
  name     = "my-gke-cluster"
  location = "us-central1"

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1
  master_authorized_networks_config = [{
    cidr_blocks = [{
      cidr_block = "0.0.0.0/0"
      display_name = "external"
    }]
  }]
}

resource "google_container_node_pool" "primary_preemptible_nodes" {
  name       = "my-node-pool"
  location   = "us-central1"
  cluster    = google_container_cluster.primary.name
  node_count = 1

  node_config {
    preemptible  = true
    machine_type = "e2-medium"

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.default.email
    oauth_scopes    = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}

```



### Secure Example

The following example will pass the google-gke-no-public-control-plane check.

```terraform

resource "google_service_account" "default" {
  account_id   = "service-account-id"
  display_name = "Service Account"
}

resource "google_container_cluster" "primary" {
  name     = "my-gke-cluster"
  location = "us-central1"

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1
  master_authorized_networks_config = [{
    cidr_blocks = [{
      cidr_block = "10.10.128.0/24"
      display_name = "internal"
    }]
  }]
}

resource "google_container_node_pool" "primary_preemptible_nodes" {
  name       = "my-node-pool"
  location   = "us-central1"
  cluster    = google_container_cluster.primary.name
  node_count = 1

  node_config {
    preemptible  = true
    machine_type = "e2-medium"

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.default.email
    oauth_scopes    = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#){:target="_blank" rel="nofollow noreferrer noopener"}

