import { useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { withObjectPanel, type ObjectRef } from '../insight/panelUrl'

/** Opens the object inspector on `r` at a given tab (?panel= plus ?ptab=),
 *  so a Helm row lands on the object's Helm tab and a GitOps row on its
 *  GitOps tab. The inspector falls back to Summary if that tab does not
 *  apply to the object. */
export function useOpenObjectTab() {
  const [, setParams] = useSearchParams()
  return useCallback(
    (r: ObjectRef, tab?: string) =>
      setParams((prev) => {
        const next = withObjectPanel(prev, r)
        if (tab) next.set('ptab', tab)
        else next.delete('ptab')
        return next
      }),
    [setParams],
  )
}
