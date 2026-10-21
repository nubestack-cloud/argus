import { describe, expect, it } from 'vitest'
import { gvkString, hasGitOpsMarkers, isGitOpsKind, kubectlResource, parseGvk, quickActionFor } from './kinds'

describe('gvkString', () => {
  it('uses the known version for a known kind', () => {
    expect(gvkString('Deployment')).toBe('apps/v1/Deployment')
    expect(gvkString('Pod')).toBe('v1/Pod')
    expect(gvkString('OCIRepository')).toBe('source.toolkit.fluxcd.io/v1beta2/OCIRepository')
  })
  it('guesses v1 for an unknown kind in the caller-supplied group', () => {
    expect(gvkString('Widget', 'example.com')).toBe('example.com/v1/Widget')
  })
})

describe('parseGvk', () => {
  it('reads both wire forms', () => {
    expect(parseGvk('apps/v1/Deployment')).toEqual({ group: 'apps', version: 'v1', kind: 'Deployment' })
    expect(parseGvk('v1/Pod')).toEqual({ version: 'v1', kind: 'Pod' })
    expect(parseGvk('apps/v1, Kind=Deployment')).toEqual({ group: 'apps', version: 'v1', kind: 'Deployment' })
    expect(parseGvk('/v1, Kind=Pod')).toEqual({ group: undefined, version: 'v1', kind: 'Pod' })
    expect(parseGvk(undefined)).toEqual({ kind: '' })
  })
})

describe('kubectlResource', () => {
  it('qualifies only non-builtin groups', () => {
    expect(kubectlResource('Deployment', 'apps')).toBe('deployment')
    expect(kubectlResource('Application', 'argoproj.io')).toBe('application.argoproj.io')
    expect(kubectlResource('Kustomization')).toBe('kustomization.kustomize.toolkit.fluxcd.io')
  })
})

describe('GitOps detection', () => {
  it('recognises controller kinds and managed-object markers', () => {
    expect(isGitOpsKind('Application')).toBe(true)
    expect(isGitOpsKind('Application', 'example.com')).toBe(false)
    expect(hasGitOpsMarkers({ 'kustomize.toolkit.fluxcd.io/name': 'x' })).toBe(true)
    expect(hasGitOpsMarkers({}, { 'argocd.argoproj.io/tracking-id': 'a' })).toBe(true)
    expect(hasGitOpsMarkers({ app: 'x' }, {})).toBe(false)
  })
  it('maps each controller kind to its one quick action', () => {
    expect(quickActionFor('Application')?.action).toBe('argoRefresh')
    expect(quickActionFor('HelmRelease')?.action).toBe('fluxReconcileHr')
    expect(quickActionFor('ApplicationSet')).toBeNull()
  })
})
