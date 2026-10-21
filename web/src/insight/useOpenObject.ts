import { useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { withObjectPanel, type ObjectRef } from './panelUrl'

/** Opens the object inspector on `r` from anywhere (sets ?panel=). */
export function useOpenObject() {
  const [, setParams] = useSearchParams()
  return useCallback((r: ObjectRef) => setParams((prev) => withObjectPanel(prev, r)), [setParams])
}
