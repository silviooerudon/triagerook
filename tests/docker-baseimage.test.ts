import { describe, it, expect } from "vitest"
import { parseFromLines, scanDockerBaseImages } from "@/lib/docker-baseimage"

const NOW = new Date("2026-05-31")
const ids = (content: string) =>
  scanDockerBaseImages(content, "Dockerfile", NOW).map((f) => f.ruleId)

describe("parseFromLines", () => {
  it("parses image:tag, strips --platform, digest, and AS alias", () => {
    const lines = [
      "FROM --platform=linux/amd64 node:18-alpine AS build",
      "FROM python:3.7@sha256:abc",
    ]
    const parsed = parseFromLines(lines)
    expect(parsed).toEqual([
      { image: "node", tag: "18-alpine", raw: "node:18-alpine", lineIndex: 0 },
      { image: "python", tag: "3.7", raw: "python:3.7", lineIndex: 1 },
    ])
  })

  it("skips multi-stage references to a previous stage and scratch", () => {
    const lines = ["FROM golang:1.20 AS builder", "FROM builder", "FROM scratch"]
    const parsed = parseFromLines(lines)
    expect(parsed.map((p) => p.image)).toEqual(["golang"])
  })

  it("handles a registry with a port without mis-splitting the tag", () => {
    const parsed = parseFromLines(["FROM registry.local:5000/team/node:16"])
    expect(parsed[0]).toMatchObject({ image: "node", tag: "16" })
  })
})

describe("scanDockerBaseImages — EOL detection", () => {
  it("flags EOL node / python / debian / ubuntu", () => {
    expect(ids("FROM node:16")).toContain("dockerfile-base-image-eol")
    expect(ids("FROM python:3.7-slim")).toContain("dockerfile-base-image-eol")
    expect(ids("FROM debian:9")).toContain("dockerfile-base-image-eol")
    expect(ids("FROM debian:stretch")).toContain("dockerfile-base-image-eol")
    expect(ids("FROM ubuntu:18.04")).toContain("dockerfile-base-image-eol")
    expect(ids("FROM ubuntu:bionic")).toContain("dockerfile-base-image-eol")
  })

  it("treats every CentOS tag as EOL (distro discontinued)", () => {
    expect(ids("FROM centos:7")).toContain("dockerfile-base-image-eol")
  })

  it("does NOT flag a currently-supported release", () => {
    expect(ids("FROM node:22-alpine")).toEqual([])
    expect(ids("FROM python:3.12")).toEqual([])
    expect(ids("FROM debian:12")).toEqual([])
    expect(ids("FROM ubuntu:24.04")).toEqual([])
  })

  it("does NOT flag current Ubuntu LTS (jammy/noble) today, but flags them past their EOL", () => {
    // Inert until their dated EOL — future-proofed in the map.
    expect(ids("FROM ubuntu:jammy")).toEqual([])
    expect(ids("FROM ubuntu:22.04")).toEqual([])
    expect(ids("FROM ubuntu:noble")).toEqual([])
    const after = new Date("2028-01-01") // past jammy (2027-04), before noble (2029-04)
    expect(
      scanDockerBaseImages("FROM ubuntu:jammy", "Dockerfile", after).map((f) => f.ruleId),
    ).toContain("dockerfile-base-image-eol")
    expect(
      scanDockerBaseImages("FROM ubuntu:22.04", "Dockerfile", after).map((f) => f.ruleId),
    ).toContain("dockerfile-base-image-eol")
    expect(
      scanDockerBaseImages("FROM ubuntu:noble", "Dockerfile", after),
    ).toEqual([]) // noble still supported in 2028
  })

  it("does NOT flag an untagged image (handled by the :latest rule)", () => {
    expect(ids("FROM node")).toEqual([])
  })

  it("emits one finding per EOL FROM in a multi-stage build", () => {
    const out = scanDockerBaseImages(
      "FROM node:16 AS build\nFROM python:3.8\nFROM node:22",
      "Dockerfile",
      NOW,
    )
    expect(out).toHaveLength(2)
    expect(out[0].lineNumber).toBe(1)
    expect(out[1].lineNumber).toBe(2)
  })

  it("escalates to high severity when a year+ past EOL", () => {
    const out = scanDockerBaseImages("FROM node:10", "Dockerfile", NOW)
    expect(out[0].severity).toBe("high")
  })

  it("does not flag a release whose EOL is still in the future at scan time", () => {
    // python 3.9 EOL 2025-10-31 — from a 2025-01 vantage point it's still supported.
    const early = new Date("2025-01-01")
    expect(
      scanDockerBaseImages("FROM python:3.9", "Dockerfile", early),
    ).toHaveLength(0)
  })
})
