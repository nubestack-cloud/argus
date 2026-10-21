// Test setup shared by every frontend test (BACKLOG P3).
//
// Deliberately minimal. The point of the first frontend test framework in this
// project is to make UI-critical LOGIC testable, not to build a mocking
// apparatus — so there is no global fetch mock and no router harness here. A test
// that needs those should set them up itself and say why, rather than inheriting
// them invisibly from this file.
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

// Unmounts anything a component test rendered. Without this, two tests that render
// the same component both find two copies in the document and the failure looks
// like a duplicate-render bug in the component rather than in the test setup.
afterEach(() => {
  cleanup()
})
