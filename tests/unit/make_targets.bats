#!/usr/bin/env bats

# Unit-level checks for the Makefile interface. These tests inspect commands with dry runs so we
# do not require Docker or cloud credentials during CI.

@test "make help lists Pulumi-oriented targets" {
  run make help
  [ "$status" -eq 0 ]
  [[ "$output" == *"pulumi-preview"* ]]
  [[ "$output" == *"pulumi-up"* ]]
  [[ "$output" == *"pulumi-refresh"* ]]
  [[ "$output" == *"pulumi-destroy"* ]]
}

@test "make start uses docker compose with .env" {
  run make -n start
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker compose --env-file .env up -d"* ]]
}

@test "make pulumi-preview executes preview inside container" {
  run make -n pulumi-preview
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker compose --env-file .env run --rm pulumi pulumi preview"* ]]
}

@test "make pulumi-up executes deployment inside container" {
  run make -n pulumi-up
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker compose --env-file .env run --rm pulumi pulumi up"* ]]
}

@test "make pulumi-refresh executes refresh inside container" {
  run make -n pulumi-refresh
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker compose --env-file .env run --rm pulumi pulumi refresh"* ]]
}

@test "make pulumi-destroy executes destroy inside container" {
  run make -n pulumi-destroy
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker compose --env-file .env run --rm pulumi pulumi destroy"* ]]
}

@test "make sh opens a throwaway shell in the Pulumi container" {
  run make -n sh
  [ "$status" -eq 0 ]
  [[ "$output" == *"docker compose --env-file .env run --rm pulumi sh"* ]]
}
