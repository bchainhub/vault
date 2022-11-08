scenario "autopilot" {
  matrix {
    arch            = ["amd64", "arm64"]
    artifact_source = ["local", "crt", "artifactory"]
    artifact_type   = ["bundle", "package"]
    distro          = ["ubuntu", "rhel"]
    edition         = ["ent"]
    seal            = ["awskms", "shamir"]

    # Currently, artifact_source:crt only uses bundles in CI
    exclude {
      artifact_source = ["crt"]
      artifact_type   = ["package"]
    }
  }

  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.ubuntu,
    provider.enos.rhel
  ]

  locals {
    build_tags = {
      "ent" = ["enterprise", "ent"]
    }
    bundle_path             = matrix.artifact_source != "artifactory" ? abspath(var.vault_bundle_path) : null
    dependencies_to_install = ["jq"]
    enos_provider = {
      rhel   = provider.enos.rhel
      ubuntu = provider.enos.ubuntu
    }
    tags = merge({
      "Project Name" : var.project_name
      "Project" : "Enos",
      "Environment" : "ci"
    }, var.tags)
    vault_instance_types = {
      amd64 = "t3a.small"
      arm64 = "t4g.small"
    }
    vault_instance_type = coalesce(var.vault_instance_type, local.vault_instance_types[matrix.arch])
    vault_install_dir_packages = {
      rhel   = "/bin"
      ubuntu = "/usr/bin"
    }
    vault_install_dir = matrix.artifact_type == "bundle" ? var.vault_install_dir : local.vault_install_dir_packages[matrix.distro]
  }

  step "build_vault" {
    module = "build_${matrix.artifact_source}"

    variables {
      build_tags           = try(var.vault_local_build_tags, local.build_tags[matrix.edition])
      bundle_path          = local.bundle_path
      goarch               = matrix.arch
      goos                 = "linux"
      artifactory_host     = matrix.artifact_source == "artifactory" ? var.artifactory_host : null
      artifactory_repo     = matrix.artifact_source == "artifactory" ? var.artifactory_repo : null
      artifactory_username = matrix.artifact_source == "artifactory" ? var.artifactory_username : null
      artifactory_token    = matrix.artifact_source == "artifactory" ? var.artifactory_token : null
      arch                 = matrix.artifact_source == "artifactory" ? matrix.arch : null
      product_version      = var.vault_product_version
      artifact_type        = matrix.artifact_type
      distro               = matrix.artifact_source == "artifactory" ? matrix.distro : null
      edition              = matrix.artifact_source == "artifactory" ? matrix.edition : null
      instance_type        = matrix.artifact_source == "artifactory" ? local.vault_instance_type : null
      revision             = var.vault_revision
    }
  }

  step "find_azs" {
    module = module.az_finder

    variables {
      instance_type = [
        local.vault_instance_type
      ]
    }
  }

  step "create_vpc" {
    module     = module.create_vpc
    depends_on = [step.find_azs]

    variables {
      ami_architectures  = [matrix.arch]
      availability_zones = step.find_azs.availability_zones
      common_tags        = local.tags
    }
  }

  step "read_license" {
    module = module.read_license

    variables {
      file_name = abspath(joinpath(path.root, "./support/vault.hclic"))
    }
  }

  # This step creates a Vault cluster using a bundle downloaded from
  # releases.hashicorp.com, with the version specified in var.vault_autopilot_initial_release
  step "create_vault_cluster" {
    module = module.vault_cluster
    depends_on = [
      step.create_vpc,
      step.build_vault,
    ]
    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      ami_id                  = step.create_vpc.ami_ids[matrix.distro][matrix.arch]
      common_tags             = local.tags
      dependencies_to_install = local.dependencies_to_install
      instance_type           = local.vault_instance_type
      kms_key_arn             = step.create_vpc.kms_key_arn
      storage_backend         = "raft"
      storage_backend_addl_config = {
        autopilot_upgrade_version = var.vault_autopilot_initial_release.version
      }
      unseal_method     = matrix.seal
      vault_install_dir = local.vault_install_dir
      vault_release     = var.vault_autopilot_initial_release
      vault_license     = step.read_license.license
      vpc_id            = step.create_vpc.vpc_id
    }
  }

  step "get_local_metadata" {
    skip_step = matrix.artifact_source != "local"
    module    = module.get_local_metadata
  }

  step "create_autopilot_upgrade_storageconfig" {
    module = module.autopilot_upgrade_storageconfig

    variables {
      vault_product_version = matrix.artifact_source == "local" ? step.get_local_metadata.version : var.vault_product_version
    }
  }

  # This step creates a new Vault cluster using a bundle or package
  # from the matrix.artifact_source, with the var.vault_product_version
  step "upgrade_vault_cluster_with_autopilot" {
    module = module.vault_cluster
    depends_on = [
      step.create_vault_cluster,
      step.build_vault,
      step.create_autopilot_upgrade_storageconfig,
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      ami_id                      = step.create_vpc.ami_ids[matrix.distro][matrix.arch]
      common_tags                 = local.tags
      dependencies_to_install     = local.dependencies_to_install
      instance_type               = local.vault_instance_type
      kms_key_arn                 = step.create_vpc.kms_key_arn
      storage_backend             = "raft"
      storage_backend_addl_config = step.create_autopilot_upgrade_storageconfig.storage_addl_config
      unseal_method               = matrix.seal
      vault_cluster_tag           = step.create_vault_cluster.vault_cluster_tag
      vault_init                  = false
      vault_install_dir           = local.vault_install_dir
      vault_license               = step.read_license.license
      vault_local_artifact_path   = local.bundle_path
      vault_artifactory_release   = matrix.artifact_source == "artifactory" ? step.build_vault.vault_artifactory_release : null
      vault_node_prefix           = "upgrade_node"
      vault_root_token            = step.create_vault_cluster.vault_root_token
      vault_unseal_when_no_init   = matrix.seal == "shamir"
      vault_unseal_keys           = matrix.seal == "shamir" ? step.create_vault_cluster.vault_unseal_keys_hex : null
      vpc_id                      = step.create_vpc.vpc_id
    }
  }

  step "verify_autopilot_upgraded_vault_cluster" {
    module     = module.vault_verify_autopilot
    depends_on = [step.upgrade_vault_cluster_with_autopilot]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_autopilot_upgrade_version = matrix.artifact_source == "local" ? step.get_local_metadata.version : var.vault_product_version
      vault_install_dir               = local.vault_install_dir
      vault_instances                 = step.create_vault_cluster.vault_instances
      vault_root_token                = step.create_vault_cluster.vault_root_token
    }
  }

  step "verify_vault_unsealed" {
    module = module.vault_verify_unsealed
    depends_on = [
      step.create_vault_cluster,
      step.upgrade_vault_cluster_with_autopilot,
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_install_dir = local.vault_install_dir
      vault_instances   = step.create_vault_cluster.vault_instances
      vault_root_token  = step.create_vault_cluster.vault_root_token
    }
  }

  step "verify_raft_auto_join_voter" {
    module = module.vault_verify_raft_auto_join_voter
    depends_on = [
      step.create_vault_cluster,
      step.upgrade_vault_cluster_with_autopilot,
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_install_dir = local.vault_install_dir
      vault_instances   = step.create_vault_cluster.vault_instances
      vault_root_token  = step.create_vault_cluster.vault_root_token
    }
  }

  output "vault_cluster_instance_ids" {
    description = "The Vault cluster instance IDs"
    value       = step.create_vault_cluster.instance_ids
  }

  output "vault_cluster_pub_ips" {
    description = "The Vault cluster public IPs"
    value       = step.create_vault_cluster.instance_public_ips
  }

  output "vault_cluster_priv_ips" {
    description = "The Vault cluster private IPs"
    value       = step.create_vault_cluster.instance_private_ips
  }

  output "vault_cluster_key_id" {
    description = "The Vault cluster Key ID"
    value       = step.create_vault_cluster.key_id
  }

  output "vault_cluster_root_token" {
    description = "The Vault cluster root token"
    value       = step.create_vault_cluster.vault_root_token
  }

  output "vault_cluster_unseal_keys_b64" {
    description = "The Vault cluster unseal keys"
    value       = step.create_vault_cluster.vault_unseal_keys_b64
  }

  output "vault_cluster_unseal_keys_hex" {
    description = "The Vault cluster unseal keys hex"
    value       = step.create_vault_cluster.vault_unseal_keys_hex
  }

  output "vault_cluster_tag" {
    description = "The Vault cluster tag"
    value       = step.create_vault_cluster.vault_cluster_tag
  }

  output "upgraded_vault_cluster_instance_ids" {
    description = "The Vault cluster instance IDs"
    value       = step.upgrade_vault_cluster_with_autopilot.instance_ids
  }

  output "upgraded_vault_cluster_pub_ips" {
    description = "The Vault cluster public IPs"
    value       = step.upgrade_vault_cluster_with_autopilot.instance_public_ips
  }

  output "upgraded_vault_cluster_priv_ips" {
    description = "The Vault cluster private IPs"
    value       = step.upgrade_vault_cluster_with_autopilot.instance_private_ips
  }
}
