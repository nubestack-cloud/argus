import type { UseQueryResult } from '@tanstack/react-query'
import type { InspectResult } from '../../api/client'
import type { ObjectRef } from '../panelUrl'
import type { DescribeResult } from '../types'
import type { ClusterFreshness } from '../useInspect'

export interface TabProps {
  target: ObjectRef
  cluster: ClusterFreshness
  /** The panel's one describe_resource read, shared by every tab. */
  describe: UseQueryResult<InspectResult<DescribeResult>>
  /** Re-targets the panel at another object. */
  open: (r: ObjectRef) => void
  /** Switches the panel to another of its tabs (the Summary's previews link
   *  to the tab that holds the full view). */
  setTab?: (id: string) => void
}
